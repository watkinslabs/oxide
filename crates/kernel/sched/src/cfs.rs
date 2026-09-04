// EEVDF fair ready tree: task-owned intrusive nodes, ordered by `(vruntime, tid)`.
// Queue mutation runs under the owning rq lock and never contacts the heap.

extern crate alloc;

use alloc::sync::Arc;
use core::cmp::Ordering as CmpOrdering;
use core::sync::atomic::Ordering;

use crate::intrusive_tree::{Adapter, IntrusiveTaskTree};
use crate::task::{SchedClass, Task, TreeRunNode};

const FAIR_SLICE_NS: u64 = 4_000_000;

struct FairTree;

// SAFETY: this adapter exclusively selects `Task::sched.se.run_node`; the
// owning CFS queue's identity claim serializes all accesses until detach.
unsafe impl Adapter for FairTree {
    fn cmp(a: &Task, b: &Task) -> CmpOrdering { cmp(key(a), key(b)) }

    unsafe fn node(task: &Task) -> &TreeRunNode {
        // SAFETY: inherited from the adapter call contract.
        unsafe { task.sched.se.run_node() }
    }

    unsafe fn node_mut(task: &Task) -> &mut TreeRunNode {
        // SAFETY: inherited from the adapter call contract.
        unsafe { task.sched.se.run_node_mut() }
    }
}

/// Allocation-free balanced fair runqueue with a cached leftmost entity.
pub(crate) struct CfsRunqueue {
    tree: IntrusiveTaskTree<FairTree>,
    queue_id: u64,
}

impl CfsRunqueue {
    /// # C: O(1)
    pub(crate) fn new() -> Self {
        Self { tree: IntrusiveTaskTree::new(), queue_id: crate::class_queue::fresh_id() }
    }

    /// # C: O(1)
    pub(crate) fn nr_running(&self) -> u32 { self.tree.len() }

    /// # C: O(1)
    #[cfg(test)]
    pub(crate) fn has_runnable(&self) -> bool { self.tree.len() != 0 }

    #[cfg(test)]
    pub(crate) fn root_height_for_test(&self) -> i32 { self.tree.height() }

    /// Sum current fair entity signals for the CPU utilization hook.
    pub(crate) fn util_avg(&self) -> u32 {
        self.tree.sum(|task| task.sched.se.avg_util.load(Ordering::Acquire))
            .min(u32::MAX as u64) as u32
    }

    /// Lowest queued virtual runtime, or zero for an empty tree. # C: O(1)
    pub(crate) fn min_vruntime(&self) -> u64 {
        self.tree.first().map_or(0, |task| key(&task).0)
    }

    /// Highest queued virtual runtime, or zero for an empty tree. # C: O(log N)
    pub(crate) fn max_vruntime(&self) -> u64 {
        self.tree.last().map_or(0, |task| key(&task).0)
    }

    /// Insert the task-owned ready node. # C: O(log N)
    pub(crate) fn enqueue(&mut self, task: Arc<Task>) -> bool {
        debug_assert!(matches!(task.sched_class(), SchedClass::Normal { .. }),
            "CfsRunqueue::enqueue: non-Normal task");
        if !crate::class_queue::claim(&task, self.queue_id) { return false; }
        let vruntime = task.sched.se.vruntime.load(Ordering::Acquire);
        let slice = task.sched.se.slice.load(Ordering::Acquire).max(FAIR_SLICE_NS);
        task.sched.se.slice.store(slice, Ordering::Release);
        let weight = task.sched.se.load.snapshot().weight >> 10;
        let request = crate::eevdf::request_delta(slice, weight);
        task.sched.se.deadline.store(vruntime.wrapping_add(request), Ordering::Release);
        let floor = self.min_vruntime();
        let total = self.tree.sum(|queued| {
            (queued.sched.se.load.snapshot().weight >> 10).max(1)
        });
        let sum = self.tree.sum_i128(|queued| {
            let key = queued.sched.se.vruntime.load(Ordering::Acquire);
            (key.wrapping_sub(floor) as i64 as i128)
                * (queued.sched.se.load.snapshot().weight >> 10).max(1) as i128
        });
        task.sched.se.vlag.store(crate::eevdf::bounded_lag(
            sum, total as u128, floor, vruntime, request), Ordering::Release);
        task.sched.se.on_rq.store(true, Ordering::Release);
        self.tree.insert(task);
        true
    }

    /// Pick and detach the earliest task. # C: O(log N)
    #[inline(never)]
    pub(crate) fn pick_leftmost(&mut self) -> Option<Arc<Task>> {
        let task = self.pick_eevdf()?;
        self.remove(&task)
    }

    /// Pick the eligible entity with the earliest virtual deadline. The
    /// vruntime tree remains the Linux leftmost index; eligibility and
    /// deadline selection are the EEVDF policy layered over that index.
    /// # C: O(N) selection, O(log N) removal
    fn pick_eevdf(&self) -> Option<Arc<Task>> {
        let total = self.tree.sum(|task| (task.sched.se.load.snapshot().weight >> 10).max(1));
        if total == 0 { return None; }
        let floor = self.min_vruntime();
        let service = self.tree.sum_i128(|task| {
            let key = task.sched.se.vruntime.load(Ordering::Acquire);
            (key.wrapping_sub(floor) as i64 as i128)
                * (task.sched.se.load.snapshot().weight >> 10).max(1) as i128
        });
        let eligible = |task: &Task| {
            crate::eevdf::eligible(service, total as u128, floor,
                task.sched.se.vruntime.load(Ordering::Acquire))
        };
        self.tree.find_best(|a, b| {
            let ae = eligible(a);
            let be = eligible(b);
            (ae && !be) || (ae == be && {
                let ad = a.sched.se.deadline.load(Ordering::Acquire);
                let bd = b.sched.se.deadline.load(Ordering::Acquire);
                ad < bd || (ad == bd && a.tid < b.tid)
            })
        })
    }

    /// Clone the earliest task without removing it. # C: O(1)
    pub(crate) fn peek_leftmost(&self) -> Option<Arc<Task>> { self.tree.first() }

    /// First queued task accepted by `predicate`, bounded by queue length.
    /// # C: O(N)
    pub(crate) fn find<F>(&self, predicate: F) -> Option<Arc<Task>>
    where F: Fn(&Task) -> bool {
        self.tree.find(predicate)
    }

    /// Remove this exact embedded node. # C: O(log N) rebalance, O(1) lookup
    pub(crate) fn remove(&mut self, task: &Task) -> Option<Arc<Task>> {
        if !crate::class_queue::owns(task, self.queue_id) { return None; }
        let removed = self.tree.remove(task).expect("fair queue claim lacks tree node");
        removed.sched.se.on_rq.store(false, Ordering::Release);
        crate::class_queue::release(&removed, self.queue_id);
        Some(removed)
    }

    #[cfg(test)]
    pub(crate) fn find_tid(&self, tid: u32) -> Option<Arc<Task>> {
        self.find(|task| task.tid == tid)
    }
}

impl Default for CfsRunqueue {
    fn default() -> Self { Self::new() }
}

impl Drop for CfsRunqueue {
    fn drop(&mut self) {
        while self.pick_leftmost().is_some() {}
    }
}

fn key(task: &Task) -> (u64, u32) {
    (task.sched.se.vruntime.load(Ordering::Acquire), task.tid)
}

fn cmp(a: (u64, u32), b: (u64, u32)) -> CmpOrdering {
    if a.0 == b.0 { return a.1.cmp(&b.1); }
    if vruntime_before(a.0, b.0) { CmpOrdering::Less }
    else { CmpOrdering::Greater }
}

/// Wrap-safe strict vruntime ordering within Linux's signed clock horizon.
pub(crate) fn vruntime_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}
