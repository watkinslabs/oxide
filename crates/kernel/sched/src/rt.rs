// RT priority array: 100 task-owned intrusive FIFO lists plus a bitmap.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::sched_enc::requeue::RequeuePos;
use crate::task::{RtRunNode, SchedClass, Task};

/// RT priorities 1..=99; slot zero remains unused.
pub(crate) const RT_PRIO_COUNT: usize = 100;

/// Allocation-free O(1) RT priority array with direct embedded-node removal.
pub(crate) struct RtRunqueue {
    heads: [Option<Arc<Task>>; RT_PRIO_COUNT],
    tails: [usize; RT_PRIO_COUNT],
    nonempty: u128,
    nr_running: u32,
    queue_id: u64,
}

impl RtRunqueue {
    /// # C: O(RT_PRIO_COUNT)
    pub(crate) fn new() -> Self {
        Self {
            heads: core::array::from_fn(|_| None),
            tails: [0; RT_PRIO_COUNT],
            nonempty: 0,
            nr_running: 0,
            queue_id: crate::class_queue::fresh_id(),
        }
    }

    /// # C: O(1)
    pub(crate) fn nr_running(&self) -> u32 { self.nr_running }

    /// # C: O(1)
    #[cfg(test)]
    pub(crate) fn has_runnable(&self) -> bool { self.nonempty != 0 }

    /// Sum runnable RT entity signals for the CPU utilization hook.
    pub(crate) fn util_avg(&self) -> u32 {
        let mut total = 0u64;
        for head in &self.heads {
            let mut current = head.as_ref().map(Arc::clone);
            while let Some(task) = current {
                total = total.saturating_add(
                    task.sched.se.avg_util.load(Ordering::Acquire));
                current = node_ref(&task).next.as_ref().map(Arc::clone);
            }
        }
        total.min(u32::MAX as u64) as u32
    }

    /// Insert at the priority FIFO tail. # C: O(1)
    #[cfg(test)]
    pub(crate) fn enqueue(&mut self, task: Arc<Task>) -> bool {
        self.enqueue_at(task, RequeuePos::Tail)
    }

    /// Insert at either end of the task's priority FIFO. # C: O(1)
    pub(crate) fn enqueue_at(&mut self, task: Arc<Task>, pos: RequeuePos) -> bool {
        let prio = priority(&task);
        if !crate::class_queue::claim(&task, self.queue_id) { return false; }
        let node = node_mut(&task);
        hal::kassert!(node.next.is_none() && node.prev == 0,
            "RT task retained stale ready-list links");
        let linked = Arc::clone(&task);
        match (self.heads[prio].take(), pos) {
            (None, _) => {
                self.tails[prio] = address(&task);
                self.heads[prio] = Some(task);
            }
            (Some(head), RequeuePos::Head) => {
                node_mut(&head).prev = address(&task);
                node_mut(&task).next = Some(head);
                self.heads[prio] = Some(task);
            }
            (Some(head), RequeuePos::Tail) => {
                self.heads[prio] = Some(head);
                let tail = self.tails[prio];
                hal::kassert!(tail != 0, "RT nonempty FIFO lacks tail");
                // SAFETY: the list head retains its tail while this queue owns it.
                let tail = unsafe { &*(tail as *const Task) };
                hal::kassert!(node_ref(tail).next.is_none(),
                    "RT FIFO tail retained successor");
                node_mut(&task).prev = address(tail);
                node_mut(tail).next = Some(task);
                self.tails[prio] = address(&linked);
            }
        }
        self.nonempty |= 1u128 << prio;
        self.nr_running += 1;
        mark_linked(&linked);
        true
    }

    /// Pick and detach the highest-priority FIFO head. # C: O(1)
    pub(crate) fn pick_highest(&mut self) -> Option<Arc<Task>> {
        let prio = self.highest()?;
        let task = self.heads[prio].as_ref().map(Arc::clone)
            .expect("RT nonempty bit lacks head");
        self.remove(&task)
    }

    /// Clone the highest-priority FIFO head without removing it. # C: O(1)
    pub(crate) fn peek_highest(&self) -> Option<Arc<Task>> {
        self.highest().and_then(|prio| self.heads[prio].as_ref().map(Arc::clone))
    }

    /// Remove this exact embedded FIFO node. # C: O(1)
    pub(crate) fn remove(&mut self, task: &Task) -> Option<Arc<Task>> {
        if !crate::class_queue::owns(task, self.queue_id) { return None; }
        let prio = priority(task);
        let previous = node_ref(task).prev;
        let slot = if previous == 0 {
            core::ptr::from_mut(&mut self.heads[prio])
        } else {
            // SAFETY: the queue-owned predecessor is retained by this FIFO.
            let previous = unsafe { &*(previous as *const Task) };
            core::ptr::from_mut(&mut node_mut(previous).next)
        };
        // SAFETY: the predecessor/head slot belongs to this exclusive queue.
        let removed = unsafe { &mut *slot }.take()?;
        hal::kassert!(core::ptr::eq(removed.as_ref(), task),
            "RT predecessor does not reference claimed task");
        let successor = node_mut(&removed).next.take();
        if let Some(successor) = successor.as_ref() {
            node_mut(successor).prev = previous;
        }
        // SAFETY: the same exclusively-owned slot now receives the successor.
        unsafe { *slot = successor; }
        if self.tails[prio] == address(task) { self.tails[prio] = previous; }
        if self.heads[prio].is_none() {
            self.tails[prio] = 0;
            self.nonempty &= !(1u128 << prio);
        }
        self.nr_running -= 1;
        node_mut(&removed).prev = 0;
        mark_detached(&removed, self.queue_id);
        Some(removed)
    }

    #[cfg(test)]
    pub(crate) fn find_tid(&self, tid: u32) -> Option<Arc<Task>> {
        for head in &self.heads {
            let mut current = head.as_ref().map(Arc::clone);
            while let Some(task) = current {
                if task.tid == tid { return Some(task); }
                current = node_ref(&task).next.as_ref().map(Arc::clone);
            }
        }
        None
    }

    /// Whether a queued peer exists at `prio`. # C: O(1)
    pub(crate) fn has_peer_at(&self, prio: u8) -> bool {
        self.heads.get(prio as usize).is_some_and(Option::is_some)
    }

    fn highest(&self) -> Option<usize> {
        if self.nonempty == 0 { None }
        else { Some((u128::BITS - 1 - self.nonempty.leading_zeros()) as usize) }
    }
}

impl Default for RtRunqueue {
    fn default() -> Self { Self::new() }
}

impl Drop for RtRunqueue {
    fn drop(&mut self) {
        while self.pick_highest().is_some() {}
    }
}

fn address(task: &Task) -> usize { core::ptr::from_ref(task) as usize }

fn priority(task: &Task) -> usize {
    let SchedClass::Rt { prio, .. } = task.sched_class() else {
        panic!("RtRunqueue::enqueue: non-RT task");
    };
    let prio = prio as usize;
    hal::kassert!(prio < RT_PRIO_COUNT, "RT priority exceeds priority array");
    prio
}

fn node_ref(task: &Task) -> &RtRunNode {
    // SAFETY: queue identity and shared queue access exclude mutation.
    unsafe { task.sched.rt.run_node() }
}

fn node_mut(task: &Task) -> &mut RtRunNode {
    // SAFETY: queue identity and exclusive queue access exclude aliases.
    unsafe { task.sched.rt.run_node_mut() }
}

fn mark_linked(task: &Task) {
    task.sched.rt.on_list.store(true, Ordering::Release);
    task.sched.rt.on_rq.store(true, Ordering::Release);
}

fn mark_detached(task: &Task, queue_id: u64) {
    let node = node_ref(task);
    hal::kassert!(node.next.is_none() && node.prev == 0,
        "detached RT task retained ready-list links");
    task.sched.rt.on_list.store(false, Ordering::Release);
    task.sched.rt.on_rq.store(false, Ordering::Release);
    crate::class_queue::release(task, queue_id);
}
