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
}

impl RunqueueInner {
    /// # C: O(RT_PRIO_COUNT)
    pub fn new(cpu: u16, idle: Arc<Task>) -> Self {
        debug_assert!(matches!(idle.sched_class(), SchedClass::Idle));
        Self {
            cpu,
            rt:  RtRunqueue::new(),
            cfs: CfsRunqueue::new(),
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
        // cgroup v2 freezer: a frozen task is held off every runqueue here
        // (the single enqueue chokepoint), so wake/yield/fork can't run it
        // until `cgroup.freeze=0` thaws it + re-enqueues.
        if task.frozen.load(core::sync::atomic::Ordering::Acquire) { return; }
        // SMP on-rq guard (Linux `p->on_rq`): a task's Arc lives in exactly
        // one runqueue's class tree at a time. If it's already queued (a
        // concurrent waker on another CPU requeued it, or the schedule path
        // re-enqueues a task a remote wake already enqueued), skip — else the
        // same Arc lands in two trees, two CPUs run it, and its resumed user
        // context (SP_EL0 / callee-saved regs) is corrupted. Cleared when the
        // task is picked/removed off the tree (cfs/rt `pick_*` + `remove`).
        if task.on_rq.swap(true, core::sync::atomic::Ordering::AcqRel) { return; }
        task.cpu.store(self.cpu, core::sync::atomic::Ordering::Release);
        match task.sched_class() {
            SchedClass::Rt { .. }     => self.rt.enqueue(task),
            SchedClass::Normal { .. } => self.cfs.enqueue(task),
            SchedClass::Idle          => panic!("RunqueueInner::enqueue: idle"),
        }
    }

    /// Linux `yield_task()` class hook for the current runnable task before
    /// `schedule()` re-enqueues it. # C: O(log N)
    pub fn yield_current_task(&mut self, task: &Task) {
        if self.nr_running() == 0 { return; }
        match task.sched_class() {
            SchedClass::Normal { .. } => {
                let floor = self.cfs.max_vruntime().saturating_add(1);
                task.lift_vruntime(floor);
            }
            SchedClass::Rt { .. } => {}
            SchedClass::Idle => {}
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
