// Re-export the hosted-tested tid registry from `crates/sched`.
// Production lives there so the registry's behaviour is locked
// down by hosted tests; this module keeps the kernel-side path
// `crate::sched::registry::*` stable for existing call sites.

#![cfg(target_os = "oxide-kernel")]

pub use sched::registry::{insert, live_tids, lookup, tasks_in_pgrp};

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sched::Task;
use sched::TaskState;

/// If `task` is currently `Stopped`, transition to `Runnable` and
/// re-enqueue into the global runqueue. Used by SIGCONT delivery.
/// No-op when the task is already runnable / running / zombie.
/// # SAFETY: caller is the syscall path on this CPU; the registry's
/// own lock plus the runqueue's inner lock serialize the wake.
/// # C: O(log N)
pub fn wake_if_stopped(task: &Arc<Task>) {
    if task.state() != TaskState::Stopped { return; }
    task.set_state(TaskState::Runnable);
    if let Some(rq) = super::runqueue::global() {
        let mut inner = rq.inner.lock();
        inner.enqueue(Arc::clone(task));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
}
