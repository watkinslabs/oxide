// `__ptrace_may_access()` — Linux `kernel/ptrace.c`.
//
// Owned here rather than in the ptrace syscall shim because it is a pure
// credential predicate that several subsystems consult: `ptrace(2)` itself,
// `kcmp(2)`, `pidfd_getfd(2)`, `process_vm_readv(2)`, and
// `perf_event_open(2)`'s `perf_check_permission()` (`kernel/events/core.c`).
// A second copy in any of those callers would be a split source of truth.

use core::sync::atomic::Ordering;

use crate::task::cap;
use crate::{Task, SUID_DUMP_USER};

/// Errno returned for every denial, matching Linux (`-EPERM`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denied;

/// Which of the caller's credential sets the check is judged by. Linux refuses
/// the check outright (`WARN` + `-EPERM`) when neither bit is given, so this is
/// an enum rather than a defaultable flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `PTRACE_MODE_REALCREDS` — the caller reached here through a syscall that
    /// explicitly names another process (`ptrace`, `kcmp`, `pidfd_getfd`,
    /// `process_vm_readv`, `perf_event_open`). Judged by `cred->uid`/`gid`.
    RealCreds,
    /// `PTRACE_MODE_FSCREDS` — the caller reached here through a FILESYSTEM
    /// syscall (every `/proc/<pid>/…` access). Judged by `cred->fsuid`/`fsgid`,
    /// which is what a process that dropped fs privileges expects to be held to.
    FsCreds,
}

/// `__ptrace_may_access(task, PTRACE_MODE_*_REALCREDS)`.
///
/// REALCREDS compares the caller's **real** uid/gid (Linux `cred->uid` /
/// `cred->gid`, *not* the effective ones — the comment in
/// `__ptrace_may_access` is explicit that euid "would make more sense" but the
/// real ids are what userspace depends on) against all three of the target's
/// uids and all three of its gids. CAP_SYS_PTRACE bypasses the comparison; the
/// dumpability gate is then applied on top of either path.
/// # C: O(1)
pub fn may_access(cur: &Task, target: &Task) -> Result<(), Denied> {
    may_access_mode(cur, target, Mode::RealCreds)
}

/// `__ptrace_may_access(task, mode)`. The only difference between the two modes
/// is WHICH pair of caller ids is compared against the target's three uids and
/// three gids; the CAP_SYS_PTRACE bypass, the same-thread-group shortcut and the
/// dumpability gate are shared.
/// # C: O(1)
pub fn may_access_mode(cur: &Task, target: &Task, mode: Mode) -> Result<(), Denied> {
    // Introspection within one's own thread group is always allowed —
    // security modules are not consulted for it either.
    if cur.tgid.load(Ordering::Acquire) == target.tgid.load(Ordering::Acquire) {
        return Ok(());
    }
    let capable = cur.has_cap(cap::SYS_PTRACE);
    if !capable && !creds_match_mode(cur, target, mode) { return Err(Denied); }
    // A target that dropped privileges became non-dumpable; only
    // CAP_SYS_PTRACE may still attach (Linux `task_still_dumpable`).
    if target.dumpable.load(Ordering::Acquire) != SUID_DUMP_USER && !capable {
        return Err(Denied);
    }
    Ok(())
}

/// The `PTRACE_MODE_REALCREDS` credential comparison. # C: O(1)
pub fn creds_match(cur: &Task, target: &Task) -> bool {
    creds_match_mode(cur, target, Mode::RealCreds)
}

/// Linux's `caller_uid`/`caller_gid` selection followed by the six-way equality
/// against the target's real/effective/saved ids. # C: O(1)
pub fn creds_match_mode(cur: &Task, target: &Task, mode: Mode) -> bool {
    let (uid, gid) = match mode {
        Mode::RealCreds => (cur.creds.ruid.load(Ordering::Acquire),
                            cur.creds.rgid.load(Ordering::Acquire)),
        Mode::FsCreds   => (cur.creds.fsuid.load(Ordering::Acquire),
                            cur.creds.fsgid.load(Ordering::Acquire)),
    };
    target.creds.ruid.load(Ordering::Acquire) == uid
        && target.creds.euid.load(Ordering::Acquire) == uid
        && target.creds.suid.load(Ordering::Acquire) == uid
        && target.creds.rgid.load(Ordering::Acquire) == gid
        && target.creds.egid.load(Ordering::Acquire) == gid
        && target.creds.sgid.load(Ordering::Acquire) == gid
}
