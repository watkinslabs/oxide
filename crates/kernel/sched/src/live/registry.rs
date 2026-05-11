// Re-export the hosted-tested tid registry from `crates/sched`.
// Production lives there so the registry's behaviour is locked
// down by hosted tests; this module keeps the kernel-side path
// `crate::registry::*` stable for existing call sites.


pub use crate::registry::{has_children, insert, live_tids, lookup, lookup_in_ns, tasks_in_pgrp, try_wake_stopped};

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use crate::Task;

/// If `task` is currently `Stopped`, transition to `Runnable` and
/// re-enqueue into the global runqueue. Used by SIGCONT delivery.
/// No-op when the task is already runnable / running / zombie.
/// State-flip lives in `crate::registry::try_wake_stopped` (hosted-
/// tested); this wrapper adds the runqueue side.
/// # SAFETY: caller is the syscall path on this CPU; the registry's
/// own lock plus the runqueue's inner lock serialize the wake.
/// # C: O(log N)
pub fn wake_if_stopped(task: &Arc<Task>) {
    if !try_wake_stopped(task) { return; }
    if let Some(rq) = super::runqueue::global() {
        let mut inner = rq.inner.lock();
        inner.enqueue(Arc::clone(task));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    // try_wake_stopped already set need_resched per 13§9; the
    // post-enqueue set here is redundant on this CPU but harmless,
    // and stays correct after the future cross-CPU IPI wakeup
    // path lands (P4-12+) where the wakeup-issuing CPU also wants
    // its own reschedule check on syscall return.
    crate::preempt::set_need_resched();
}
