// ptrace(2) permission gate — single choke point for every request the
// `101_ptrace` shim and `ptrace_fpu` dispatch. Linux `kernel/ptrace.c`:
// `__ptrace_may_access`, `ptrace_attach`, `ptrace_check_attach`.
//
// Compiled hosted as well as `oxide-kernel`: the checks touch only
// `sched::Task` fields, so they are unit-testable without a live scheduler.

use core::sync::atomic::Ordering;
use sched::{Task, TaskState};
use syscall::errno::Errno;

/// Linux `SUID_DUMP_USER` — the only dumpability value that lets a
/// same-uid tracer attach without CAP_SYS_PTRACE.
pub const SUID_DUMP_USER: u8 = 1;

/// Linux `__ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS)`.
///
/// REALCREDS compares the caller's **real** uid/gid (Linux `cred->uid` /
/// `cred->gid`, *not* the effective ones — the comment in
/// `__ptrace_may_access` is explicit that euid "would make more sense" but
/// the real ids are what userspace depends on) against all three of the
/// target's uids and all three of its gids. CAP_SYS_PTRACE bypasses the
/// comparison; the dumpability gate is then applied on top of either path.
/// # C: O(1)
///
/// The predicate itself is owned by `sched::ptrace_access` — `kcmp(2)`,
/// `pidfd_getfd(2)` and `perf_event_open(2)`'s `perf_check_permission()` all
/// consult it, so it cannot live inside one syscall's shim.
pub fn may_access(cur: &Task, target: &Task) -> Result<(), Errno> {
    sched::ptrace_access::may_access(cur, target).map_err(|_| Errno::Eperm)
}

/// The ATTACH-class form: the credential ladder plus
/// `security_ptrace_access_check`, which is where
/// `/proc/sys/kernel/yama/ptrace_scope` is enforced. `PTRACE_ATTACH` and
/// `PTRACE_SEIZE` are ATTACH-class; nothing else in the request table is.
/// # C: O(N_relations + depth)
pub fn may_attach_access(cur: &Task, target: &Task) -> Result<(), Errno> {
    use sched::ptrace_access::{Access, Mode};
    sched::ptrace_access::may_access_full(cur, target, Mode::RealCreds, Access::Attach)
        .map_err(|_| Errno::Eperm)
}

/// Linux `ptrace_traceme` calls `security_ptrace_traceme(current->parent)`
/// under the tasklist lock; Yama refuses on its two highest scopes.
/// # C: O(1)
pub fn may_traceme(parent: &Task) -> Result<(), Errno> {
    sched::yama::ptrace_traceme(parent).map_err(|()| Errno::Eperm)
}

/// Linux `ptrace_attach` gate, in Linux's order. `is_kthread` is the
/// `PF_KTHREAD` test (a task with no user address space); `already_traced`
/// is `task->ptrace`; `exiting` is `task->exit_state`. Every failure is
/// EPERM — a caller cannot distinguish "not permitted" from "already traced".
/// # C: O(1)
pub fn may_attach(cur: &Task, target: &Task, is_kthread: bool, exiting: bool)
    -> Result<(), Errno>
{
    if is_kthread { return Err(Errno::Eperm); }
    if cur.tgid.load(Ordering::Acquire) == target.tgid.load(Ordering::Acquire) {
        return Err(Errno::Eperm);
    }
    may_attach_access(cur, target)?;
    if exiting { return Err(Errno::Eperm); }
    if target.traced_by.load(Ordering::Acquire) != 0 { return Err(Errno::Eperm); }
    Ok(())
}

/// Linux `ptrace_check_attach`: the caller must be the recorded tracer, and
/// — unless the request is KILL or INTERRUPT — the target must be
/// ptrace-stopped. Either failure is ESRCH: from ptrace's point of view a
/// pid it does not trace does not exist.
/// # C: O(1)
pub fn check_attach(cur: &Task, target: &Task, need_stopped: bool) -> Result<(), Errno> {
    if target.traced_by.load(Ordering::Acquire) != cur.tid { return Err(Errno::Esrch); }
    if need_stopped && target.state() != TaskState::Stopped { return Err(Errno::Esrch); }
    Ok(())
}

/// Boolean form retained for `ptrace_fpu`'s call sites.
/// # C: O(1)
pub fn require_tracer(cur: &Task, target: &Task, need_stopped: bool) -> bool {
    check_attach(cur, target, need_stopped).is_ok()
}

#[cfg(test)]
#[path = "perm/tests.rs"] mod tests;
