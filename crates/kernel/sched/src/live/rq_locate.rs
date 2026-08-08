// Locate the runqueue a task is ACTUALLY queued on — Linux `task_rq_lock`.
//
// A task's `Arc` may live in exactly one runqueue's class tree at a time
// (`RunqueueInner::enqueue`'s `on_rq` guard). Any operation that has to
// re-place a queued task must therefore dequeue it from ITS rq — the one
// named by `task_rq(p)` — not from the rq of whatever CPU happens to be
// running the syscall. Linux `__sched_setscheduler` opens with
// `rq = task_rq_lock(p, &rf)`, and both
// `sched_change_begin()` and `sched_change_end()` independently recompute
// `rq = task_rq(p)` and `lockdep_assert_rq_held(rq)`, so the dequeue and the
// matching enqueue provably target the same, task-owned runqueue.
//
// Getting this wrong is not a mere accounting slip. Clearing `on_rq` and
// enqueueing on the caller's rq bypasses the double-enqueue guard, leaving
// one `Arc<Task>` in TWO trees: two CPUs pick it, two CPUs run it, and its
// saved register context is corrupted. Linux has no such path anywhere —
// cross-rq movement always goes dequeue-from-source -> `set_task_cpu` ->
// enqueue-on-dest, bridged by `TASK_ON_RQ_MIGRATING`.
//
// The walk is generic over the runqueue accessor so the decision logic is
// exercised by hosted tests against real `Runqueue` / `RunqueueInner` /
// `Spinlock` instances, without depending on the `GLOBALS` array (which only
// the owning CPU may install into, and which is process-global and therefore
// unusable from parallel `cargo test` threads).

use alloc::sync::Arc;

use crate::Task;
use super::runqueue::{RqIrq, Runqueue};

/// Dequeue `tid` from whichever runqueue currently holds it, under that
/// runqueue's own lock. Returns the task and the CPU it was dequeued from, or
/// `None` if it is queued nowhere (blocked, exiting, or currently RUNNING —
/// a running task is not in any tree and has `on_rq == false`).
///
/// One rq lock at a time: no nesting, so no lock-order hazard (`06§3.6`).
/// `remove` already clears `on_rq`, so the returned task is safe to re-enqueue.
/// # C: O(N_cpus · log N)
pub fn dequeue_from_owning_rq_with<'a, F>(get_rq: &F, tid: u32) -> Option<(Arc<Task>, u32)>
where F: Fn(u32) -> Option<&'a Runqueue> {
    for cpu in 0..cpu::MAX_CPUS as u32 {
        let rq = match get_rq(cpu) { Some(r) => r, None => continue };
        let removed = {
            let mut inner = rq.inner.lock_irqsave::<RqIrq>();
            let r = inner.remove(tid);
            if r.is_some() { rq.publish_nr_running(inner.nr_running()); }
            r
        };
        if let Some(task) = removed { return Some((task, cpu)); }
    }
    None
}

/// Enqueue `task` onto `cpu`'s runqueue, keeping the `nr_running` mirror in
/// step. Idle tasks are never queued (`13§2` invariant 7).
///
/// Returns whether the task was actually placed. `false` means `cpu` has no
/// installed runqueue and the task was NOT queued — a caller that had already
/// dequeued it holds the last reference to a runnable task that is now on no
/// runqueue at all, and must put it somewhere. The result is `#[must_use]`
/// because ignoring it loses the task silently: it simply never runs again,
/// with no fault and no log line.
/// # C: O(log N)
#[must_use]
pub fn enqueue_on_with<'a, F>(get_rq: &F, cpu: u32, task: Arc<Task>) -> bool
where F: Fn(u32) -> Option<&'a Runqueue> {
    if matches!(task.sched_class(), crate::SchedClass::Idle) { return true; }
    match get_rq(cpu) {
        Some(rq) => {
            let mut inner = rq.inner.lock_irqsave::<RqIrq>();
            inner.enqueue(task);
            rq.publish_nr_running(inner.nr_running());
            true
        }
        None => false,
    }
}

/// Change `task`'s scheduling class, re-placing it on the runqueue it is
/// actually queued on. Linux `__sched_setscheduler` under `task_rq_lock`:
/// dequeue there, mutate, enqueue back there.
///
/// A task queued nowhere (blocked, or currently running on some CPU) only has
/// its class updated — matching Linux's `ctx->queued` / `ctx->running`
/// idempotence, where a task that was not queued is not enqueued.
/// # C: O(N_cpus · log N)
pub fn set_class_with<'a, F>(get_rq: &F, task: &Arc<Task>, new: crate::SchedClass)
where F: Fn(u32) -> Option<&'a Runqueue> {
    match dequeue_from_owning_rq_with(get_rq, task.tid) {
        Some((dequeued, cpu)) => {
            task.set_sched_class(new);
            // Back onto the SAME runqueue: Linux `sched_change_end` re-reads
            // `task_rq(p)`, which the held rq lock kept from changing. Moving
            // it to the caller's CPU here would be a migration the affinity
            // mask never authorised.
            // Same rq it was just dequeued from, so placement cannot fail.
            let _ = enqueue_on_with(get_rq, cpu, dequeued);
        }
        None => task.set_sched_class(new),
    }
}

#[cfg(test)]
mod tests;
