// Re-export the hosted-tested tid registry from `crates/sched`.
// Production lives there so the registry's behaviour is locked
// down by hosted tests; this module keeps the kernel-side path
// `crate::registry::*` stable for existing call sites.

pub use crate::registry::{
    acquire_pidfd_in_namespace, display_vpid, display_vtid, has_children, has_wait_children, insert,
    live_counts, live_tids, live_vpids, lookup, lookup_by_vpid, lookup_in_namespace, mark_reaped, parent_vpid,
    peek_child_stop_event, pidfd_exit_ready, resolve_user_pid, take_child_stop_event, tasks_in_pgrp,
    thread_entries, try_wake_stopped, PidfdAcquireError, PidfdKind,
};

use crate::Task;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

/// If `task` is currently `Stopped`, transition to `Runnable` and
/// re-enqueue into the global runqueue. Used by SIGCONT delivery.
/// No-op when the task is already runnable / running / zombie.
/// State-flip lives in `crate::registry::try_wake_stopped` (hosted-
/// tested); this wrapper adds the runqueue side.
/// # SAFETY: caller is the syscall path on this CPU; the registry's
/// own lock plus the runqueue's inner lock serialize the wake.
/// # C: O(log N)
pub fn wake_if_stopped(task: &Arc<Task>) {
    if !try_wake_stopped(task) {
        return;
    }
    // Placement goes through `place_runnable` (Linux `ttwu`'s
    // `select_task_rq`), not a raw local enqueue: a task pinned away from the
    // CPU that delivered SIGCONT must not be resumed on it.
    // SAFETY: wake site — the caller owns an Arc and `try_wake_stopped` just
    // claimed the Stopped->Runnable transition, so the task is on no runqueue.
    unsafe { super::ttwu::place_runnable(Arc::clone(task), false); }
    // try_wake_stopped already set need_resched per 13§9; the
    // post-enqueue set here is redundant on this CPU but harmless,
    // and stays correct after the future cross-CPU IPI wakeup
    // path lands (P4-12+) where the wakeup-issuing CPU also wants
    // its own reschedule check on syscall return.
    crate::preempt::set_need_resched();
}
