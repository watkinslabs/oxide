// Linux `thread_info::syscall_work` subset.
//
// Syscall tracing is globally registered, but the entry/exit decision is
// task-local: `syscall_regfunc` stamps SYSCALL_WORK_SYSCALL_TRACEPOINT on every
// task under tasklist_lock, new tasks receive the current state at publication,
// and the dispatcher reads only its current task's word. This keeps one fast
// work test in the syscall path while tracefs owns event enablement.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::Task;

/// Linux `SYSCALL_WORK_SYSCALL_TRACEPOINT`.
pub const TRACEPOINT: u32 = 1 << 0;

/// Global registration state used only to reconcile tasks entering REG.
/// The per-task word, not this global, is the syscall hot-path owner.
static TRACEPOINT_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Register or unregister the syscall tracepoint family.
///
/// Tracefs serializes zero/nonzero transitions under its tracepoint lock.
/// Publishing the global state before walking REG closes both races with a new
/// task: an insert before this store is caught by the walk; an insert after it
/// reconciles from the new value while holding the same task-list lock.
/// # C: O(N_tasks) on a zero/nonzero transition
pub fn set_tracepoint_active(active: bool) {
    if TRACEPOINT_ACTIVE.swap(active, Ordering::AcqRel) == active { return; }
    crate::registry::set_syscall_tracepoint_work_all(active);
}

/// Stamp a task being inserted into the live registry from the registration
/// state. Called while REG is held, which orders it against the global walk.
/// # C: O(1)
pub(crate) fn reconcile_new_task(task: &Task) {
    set_task_tracepoint(task, TRACEPOINT_ACTIVE.load(Ordering::Acquire));
}

/// Does this task owe syscall tracepoint work at this entry/exit boundary?
/// # C: O(1)
#[inline]
pub fn tracepoint_pending(task: Option<&Task>) -> bool {
    task.map_or(false, |t| t.syscall_work.load(Ordering::Acquire) & TRACEPOINT != 0)
}

/// Update one task's work word without disturbing future syscall-work bits.
/// # C: O(1)
pub(crate) fn set_task_tracepoint(task: &Task, active: bool) {
    if active {
        task.syscall_work.fetch_or(TRACEPOINT, Ordering::Release);
    } else {
        task.syscall_work.fetch_and(!TRACEPOINT, Ordering::Release);
    }
}

/// Is the syscall tracepoint family registered? Control-plane observation;
/// syscall entry must use [`tracepoint_pending`] instead. # C: O(1)
pub fn tracepoint_active() -> bool {
    TRACEPOINT_ACTIVE.load(Ordering::Acquire)
}
