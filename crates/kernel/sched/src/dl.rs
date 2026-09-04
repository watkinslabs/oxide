// Deadline-class ready tree: earliest deadline first over task-owned nodes.

extern crate alloc;

use alloc::sync::Arc;
use core::cmp::Ordering as CmpOrdering;
use core::sync::atomic::Ordering;

use crate::intrusive_tree::{Adapter, IntrusiveTaskTree};
use crate::task::{SchedClass, Task, TreeRunNode};

struct DeadlineTree;

// SAFETY: this adapter exclusively selects `Task::sched.dl.ready_node`; the
// owning DL queue's identity claim serializes every access until detach.
unsafe impl Adapter for DeadlineTree {
    fn cmp(a: &Task, b: &Task) -> CmpOrdering {
        let a_deadline = a.effective_dl_deadline();
        let b_deadline = b.effective_dl_deadline();
        if a_deadline == b_deadline { return a.tid.cmp(&b.tid); }
        if crate::deadline::dl_time_before(a_deadline, b_deadline) {
            CmpOrdering::Less
        } else {
            CmpOrdering::Greater
        }
    }

    unsafe fn node(task: &Task) -> &TreeRunNode {
        // SAFETY: inherited from the adapter call contract.
        unsafe { task.sched.dl.ready_node() }
    }

    unsafe fn node_mut(task: &Task) -> &mut TreeRunNode {
        // SAFETY: inherited from the adapter call contract.
        unsafe { task.sched.dl.ready_node_mut() }
    }
}

/// Allocation-free cached EDF ready tree.
pub(crate) struct DlRunqueue {
    tree: IntrusiveTaskTree<DeadlineTree>,
    queue_id: u64,
}

impl DlRunqueue {
    /// # C: O(1)
    pub(crate) fn new() -> Self {
        Self { tree: IntrusiveTaskTree::new(), queue_id: crate::class_queue::fresh_id() }
    }

    /// # C: O(1)
    pub(crate) fn nr_running(&self) -> u32 { self.tree.len() }

    #[cfg(test)]
    pub(crate) fn root_height_for_test(&self) -> i32 { self.tree.height() }

    /// Sum runnable deadline entity signals for the CPU utilization hook.
    pub(crate) fn util_avg(&self) -> u32 {
        self.tree.sum(|task| task.sched.se.avg_util.load(Ordering::Acquire))
            .min(u32::MAX as u64) as u32
    }

    /// Earliest absolute deadline queued, or `None`. # C: O(1)
    #[cfg(test)]
    pub(crate) fn earliest_deadline(&self) -> Option<u64> {
        self.tree.first().map(|task| task.effective_dl_deadline())
    }

    /// Insert keyed on the entity's current absolute deadline. # C: O(log N)
    pub(crate) fn enqueue(&mut self, task: Arc<Task>) -> bool {
        debug_assert!(matches!(task.sched_class(), SchedClass::Deadline),
            "DlRunqueue::enqueue: non-deadline task");
        if !crate::class_queue::claim(&task, self.queue_id) { return false; }
        task.sched.dl.bind_owner(&task);
        self.tree.insert(task);
        true
    }

    /// Pick and detach the earliest-deadline entity. # C: O(log N)
    pub(crate) fn pick_earliest(&mut self) -> Option<Arc<Task>> {
        let task = self.tree.first()?;
        self.remove(&task)
    }

    /// Clone the earliest entity without removing it. # C: O(1)
    pub(crate) fn peek_earliest(&self) -> Option<Arc<Task>> { self.tree.first() }

    /// Remove this exact embedded node. # C: O(log N) rebalance, O(1) lookup
    pub(crate) fn remove(&mut self, task: &Task) -> Option<Arc<Task>> {
        if !crate::class_queue::owns(task, self.queue_id) { return None; }
        let removed = self.tree.remove(task).expect("deadline queue claim lacks tree node");
        crate::class_queue::release(&removed, self.queue_id);
        Some(removed)
    }

    #[cfg(test)]
    pub(crate) fn find_tid(&self, tid: u32) -> Option<Arc<Task>> {
        self.tree.find(|task| task.tid == tid)
    }
}

impl Default for DlRunqueue {
    fn default() -> Self { Self::new() }
}

impl Drop for DlRunqueue {
    fn drop(&mut self) {
        while self.pick_earliest().is_some() {}
    }
}
