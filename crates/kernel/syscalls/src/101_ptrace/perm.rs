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
pub fn may_access(cur: &Task, target: &Task) -> Result<(), Errno> {
    // Introspection within one's own thread group is always allowed —
    // security modules are not consulted for it either.
    if cur.tgid.load(Ordering::Acquire) == target.tgid.load(Ordering::Acquire) {
        return Ok(());
    }
    let cap = cur.has_cap(sched::cap::SYS_PTRACE);
    if !cap && !creds_match(cur, target) { return Err(Errno::Eperm); }
    // A target that dropped privileges became non-dumpable; only
    // CAP_SYS_PTRACE may still attach (Linux `task_still_dumpable`).
    if target.dumpable.load(Ordering::Acquire) != SUID_DUMP_USER && !cap {
        return Err(Errno::Eperm);
    }
    Ok(())
}

/// The `PTRACE_MODE_REALCREDS` credential comparison.
/// # C: O(1)
fn creds_match(cur: &Task, target: &Task) -> bool {
    let uid = cur.creds.ruid.load(Ordering::Acquire);
    let gid = cur.creds.rgid.load(Ordering::Acquire);
    target.creds.ruid.load(Ordering::Acquire) == uid
        && target.creds.euid.load(Ordering::Acquire) == uid
        && target.creds.suid.load(Ordering::Acquire) == uid
        && target.creds.rgid.load(Ordering::Acquire) == gid
        && target.creds.egid.load(Ordering::Acquire) == gid
        && target.creds.sgid.load(Ordering::Acquire) == gid
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
    may_access(cur, target)?;
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
