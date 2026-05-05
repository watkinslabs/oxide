// Re-export the hosted-tested tid registry from `crates/sched`.
// Production lives there so the registry's behaviour is locked
// down by hosted tests; this module keeps the kernel-side path
// `crate::sched::registry::*` stable for existing call sites.

#![cfg(target_os = "oxide-kernel")]

pub use sched::registry::{insert, live_tids, lookup, tasks_in_pgrp, try_wake_stopped};

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sched::Task;

/// If `task` is currently `Stopped`, transition to `Runnable` and
/// re-enqueue into the global runqueue. Used by SIGCONT delivery.
/// No-op when the task is already runnable / running / zombie.
/// State-flip lives in `sched::registry::try_wake_stopped` (hosted-
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
}
