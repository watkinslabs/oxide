// Per-CPU runqueue per `13§6` / `13§7`. Holds the RT + CFS class
// runqueues plus an idle task; `pick_next_task` enforces invariant 6
// (RT preempts Normal, `13§2`) and invariant 7 (idle uniqueness,
// `13§2`).
//
// Concurrency: the spec wraps `RunqueueInner` in a per-CPU spinlock
// (class `Runqueue`, `06§3.6`); `nr_running` / `current` /
// `preempt_count` / `need_resched` live as atomics for lock-free reads
// (`13§6`). This PR exposes the inner state directly so the runqueue
// logic is hosted-testable; the spinlock + atomic outer skin land
// alongside `schedule()` once HAL `Context` exists.

extern crate alloc;
use alloc::sync::Arc;

use crate::cfs::CfsRunqueue;
use crate::rt::RtRunqueue;
use crate::task::{SchedClass, Task};

/// Per-CPU runqueue inner state. Mutated under the per-CPU `Runqueue`
/// spinlock once that's wired (`13§6`).
pub struct RunqueueInner {
    pub cpu: u16,
    pub rt:  RtRunqueue,
    pub cfs: CfsRunqueue,
    /// Per-CPU idle task. Always Runnable; never on RT/CFS lists per
    /// `13§2` invariant 7.
    pub idle: Arc<Task>,
    /// Currently-running task (== `idle` when nothing else).
    pub current: Arc<Task>,
}

impl RunqueueInner {
    /// # C: O(RT_PRIO_COUNT)
    pub fn new(cpu: u16, idle: Arc<Task>) -> Self {
        debug_assert!(matches!(idle.class, SchedClass::Idle));
        Self {
            cpu,
            rt:  RtRunqueue::new(),
            cfs: CfsRunqueue::new(),
            current: Arc::clone(&idle),
            idle,
        }
    }

    /// # C: O(1)
    pub fn nr_running(&self) -> u32 {
        self.rt.nr_running() + self.cfs.nr_running()
    }

    /// Enqueue a task by class. Idle tasks are rejected — they live in
    /// `self.idle` and never appear on the RT/CFS lists per `13§2`.
    /// # C: O(log N) (CFS) / O(1) (RT)
    pub fn enqueue(&mut self, task: Arc<Task>) {
        match task.class {
            SchedClass::Rt { .. }     => self.rt.enqueue(task),
            SchedClass::Normal { .. } => self.cfs.enqueue(task),
            SchedClass::Idle          => panic!("RunqueueInner::enqueue: idle"),
        }
    }

    /// Pick + remove the next task per `13§7`. Falls back to the per-CPU
    /// idle task if both class queues are empty.
    /// # C: O(log N) (CFS path) / O(1) (RT path)
    pub fn pick_next_task(&mut self) -> Arc<Task> {
        if let Some(t) = self.rt.pick_highest()  { return t; }
        if let Some(t) = self.cfs.pick_leftmost() { return t; }
        Arc::clone(&self.idle)
    }

    /// Peek at the next pick without removing. Used by `need_resched`
    /// computation when a wakeup might outrank `current` (`13§9`).
    /// # C: O(log N) (CFS path) / O(1) (RT path)
    pub fn peek_next_task(&self) -> Arc<Task> {
        if let Some(t) = self.rt.peek_highest()   { return Arc::clone(t); }
        if let Some(t) = self.cfs.peek_leftmost() { return Arc::clone(t); }
        Arc::clone(&self.idle)
    }

    /// Remove a task by `tid` from whichever class list holds it.
    /// `None` if not on any list (e.g. currently running, idle, or
    /// already migrated away).
    /// # C: O(N)
    pub fn remove(&mut self, tid: u32) -> Option<Arc<Task>> {
        if let Some(t) = self.rt.remove(tid)  { return Some(t); }
        if let Some(t) = self.cfs.remove(tid) { return Some(t); }
        None
    }
}
