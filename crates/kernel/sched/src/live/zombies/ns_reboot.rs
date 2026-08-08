// Linux `struct pid_namespace::reboot`,
// written by `reboot_pid_ns` and consumed
// by `zap_pid_ns_processes`:
//
//     if (pid_ns->reboot)
//             current->signal->group_exit_code = pid_ns->reboot;
//
// A container that calls `reboot(2)` does not reboot the machine — its
// namespace dies and its init reports SIGHUP (RESTART/RESTART2) or SIGINT
// (HALT/POWER_OFF) to the supervisor outside, which is how the supervisor
// tells "restart me" from "stop me". Dropping the marker would make every
// in-namespace reboot look like an ordinary SIGKILL and turn a container
// restart request into a stop.
//
// oxide has no `struct pid_namespace` payload — namespaces carry identity
// only (`namespace_identity`) — so the field lives here, with the exit path
// that consumes it, keyed by the same namespace id `pid_namespace_id` returns.

use core::sync::atomic::Ordering;

use sync::{Spinlock, TaskList as TaskListClass};

use crate::Task;

use super::pidns::pid_namespace_id;

/// Namespaces that may hold a pending reboot marker at once. One entry per
/// namespace that called `reboot(2)` and has not yet finished dying; a
/// namespace consumes its entry in its init's exit path.
const MAX_PENDING: usize = 16;

/// `(pid namespace id, signal)`. `signal == 0` means the slot is free.
static PENDING: Spinlock<[(u64, i32); MAX_PENDING], TaskListClass> =
    Spinlock::new([(0, 0); MAX_PENDING]);

/// `pid_ns->reboot = SIGHUP | SIGINT` for the calling task's namespace.
/// Overwrites an existing marker, as the plain assignment in Linux does.
/// # C: O(MAX_PENDING)
pub fn set_pid_namespace_reboot(task: &Task, signo: i32) {
    let Some(ns) = pid_namespace_id(task) else { return };
    if signo == 0 { return; }
    let mut slots = PENDING.lock();
    if let Some(slot) = slots.iter_mut().find(|(id, sig)| *sig != 0 && *id == ns) {
        slot.1 = signo;
        return;
    }
    if let Some(slot) = slots.iter_mut().find(|(_, sig)| *sig == 0) {
        *slot = (ns, signo);
    }
}

/// Read and clear the marker for `task`'s namespace. Called once, from the
/// namespace init's exit path.
/// # C: O(MAX_PENDING)
pub fn take_pid_namespace_reboot(task: &Task) -> Option<i32> {
    let ns = pid_namespace_id(task)?;
    let mut slots = PENDING.lock();
    let slot = slots.iter_mut().find(|(id, sig)| *sig != 0 && *id == ns)?;
    let signo = slot.1;
    *slot = (0, 0);
    Some(signo)
}

/// `zap_pid_ns_processes`' closing assignment: republish the dying namespace
/// init's status as a death by the recorded signal, overriding the SIGKILL
/// that felled it. Returns the new INTERNAL status when a marker was pending.
/// # C: O(MAX_PENDING)
pub fn apply_pid_namespace_reboot_status(task: &Task) -> Option<i32> {
    let signo = take_pid_namespace_reboot(task)?;
    let status = crate::signum::killed_status(signo as u32);
    task.exit_status.store(status, Ordering::Release);
    task.thread_group.force_group_exit_code(status);
    Some(status)
}
