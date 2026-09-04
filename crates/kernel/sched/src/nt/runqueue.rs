use alloc::collections::VecDeque;
use alloc::sync::Arc;
use crate::task::{SchedClass, Task};

const NT_LEVELS: usize = 32;

pub(crate) struct NtRunqueue {
    queues: [VecDeque<Arc<Task>>; NT_LEVELS],
    nonempty: u32,
    nr_running: u32,
    queue_id: u64,
}

impl NtRunqueue {
    pub(crate) fn new() -> Self {
        Self { queues: core::array::from_fn(|_| VecDeque::new()), nonempty: 0,
            nr_running: 0, queue_id: crate::class_queue::fresh_id() }
    }
    pub(crate) fn nr_running(&self) -> u32 { self.nr_running }
    pub(crate) fn util_avg(&self) -> u32 {
        self.queues.iter().flat_map(|queue| queue.iter())
            .map(|task| task.sched.se.avg_util.load(core::sync::atomic::Ordering::Acquire))
            .sum::<u64>().min(u32::MAX as u64) as u32
    }
    pub(crate) fn has_peer_at(&self, level: u8) -> bool {
        !self.queues[level as usize].is_empty()
    }
    pub(crate) fn enqueue(&mut self, task: Arc<Task>, front: bool) -> bool {
        let SchedClass::NtFixed { level, .. } = task.sched_class() else {
            panic!("NtRunqueue::enqueue: non-NT task")
        };
        if !crate::class_queue::claim(&task, self.queue_id) { return false; }
        let bucket = &mut self.queues[level as usize];
        if front { bucket.push_front(task); } else { bucket.push_back(task); }
        self.nonempty |= 1u32 << level;
        self.nr_running += 1;
        true
    }
    pub(crate) fn pick_highest(&mut self) -> Option<Arc<Task>> {
        if self.nonempty == 0 { return None; }
        let level = (u32::BITS - 1 - self.nonempty.leading_zeros()) as usize;
        let task = self.queues.get_mut(level)?.pop_front()?;
        if self.queues[level].is_empty() { self.nonempty &= !(1u32 << level); }
        self.nr_running -= 1;
        crate::class_queue::release(&task, self.queue_id);
        Some(task)
    }
    pub(crate) fn peek_highest(&self) -> Option<Arc<Task>> {
        if self.nonempty == 0 { return None; }
        let level = (u32::BITS - 1 - self.nonempty.leading_zeros()) as usize;
        self.queues[level].front().map(Arc::clone)
    }
    pub(crate) fn remove(&mut self, task: &Task) -> Option<Arc<Task>> {
        let SchedClass::NtFixed { level, .. } = task.sched_class() else { return None };
        let bucket = &mut self.queues[level as usize];
        let index = bucket.iter().position(|candidate| core::ptr::eq(candidate.as_ref(), task))?;
        let removed = bucket.remove(index)?;
        if bucket.is_empty() { self.nonempty &= !(1u32 << level); }
        self.nr_running -= 1;
        crate::class_queue::release(&removed, self.queue_id);
        Some(removed)
    }
}

impl Default for NtRunqueue { fn default() -> Self { Self::new() } }
impl Drop for NtRunqueue { fn drop(&mut self) { while self.pick_highest().is_some() {} } }

#[cfg(test)]
mod tests {
    use super::*;
    fn task(tid: u32, level: u8) -> Arc<Task> {
        Arc::new(Task::new(tid, "nt-fixed", SchedClass::NtFixed { level, quantum: 3 }))
    }
    #[test]
    fn highest_level_preempts_lower_levels() {
        let mut q = NtRunqueue::new();
        assert!(q.enqueue(task(1, 4), false));
        assert!(q.enqueue(task(2, 27), false));
        assert_eq!(q.pick_highest().unwrap().tid, 2);
        assert_eq!(q.pick_highest().unwrap().tid, 1);
    }
    #[test]
    fn equal_level_is_fifo_until_explicit_rotation() {
        let mut q = NtRunqueue::new();
        let first = task(1, 12);
        assert!(q.enqueue(Arc::clone(&first), false));
        assert!(q.enqueue(task(2, 12), false));
        assert_eq!(q.pick_highest().unwrap().tid, 1);
        assert!(q.enqueue(first, false));
        assert_eq!(q.pick_highest().unwrap().tid, 2);
        assert_eq!(q.pick_highest().unwrap().tid, 1);
    }
    #[test]
    fn invalid_level_is_rejected_by_task_state_constructor() {
        assert!(std::panic::catch_unwind(|| {
            Task::new(3, "invalid", SchedClass::NtFixed { level: 32, quantum: 1 });
        }).is_err());
    }
}
