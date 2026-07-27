// Linux `kernel/sys.c` uid-family work fns: `__sys_setuid`, `__sys_setreuid`,
// `__sys_setresuid`, plus the trivial getters.
//
// Every work fn takes `&Task` so the full transition (including the error
// ORDER) is hosted-testable without a live runqueue.

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::Task;
use super::capfix::{task_fix_setuid, UidTriple};
use super::commit::{commit_creds, CredIdentity};
use super::limits::{id_valid, ID_UNCHANGED};

/// # C: O(1)
fn eperm() -> i64 { -(Errno::Eperm.as_i32() as i64) }
/// # C: O(1)
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// Read the task's `(ruid, euid, suid)`. # C: O(1)
fn triple(cur: &Task) -> UidTriple {
    UidTriple {
        r: cur.creds.ruid.load(Ordering::Acquire),
        e: cur.creds.euid.load(Ordering::Acquire),
        s: cur.creds.suid.load(Ordering::Acquire),
    }
}

/// Publish a uid triple plus the fsuid Linux derives from it, then run the
/// `LSM_SETID_*` capability juggle and the `commit_creds` side effects.
/// # C: O(1); # Lk: TaskList
fn publish(cur: &Task, old: UidTriple, new: UidTriple, fsuid: u32) {
    let identity = CredIdentity::capture(cur);
    cur.creds.ruid.store(new.r, Ordering::Release);
    cur.creds.euid.store(new.e, Ordering::Release);
    cur.creds.suid.store(new.s, Ordering::Release);
    cur.creds.fsuid.store(fsuid, Ordering::Release);
    task_fix_setuid(cur, old, new);
    commit_creds(cur, identity);
}

/// `sys_getuid` — slot 102. Returns the real uid. # C: O(1)
pub fn sys_getuid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => t.creds.ruid.load(Ordering::Acquire) as i64,
        None    => 0,
    }
}

/// `sys_geteuid` — slot 107. Returns the effective uid. # C: O(1)
pub fn sys_geteuid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => t.creds.euid.load(Ordering::Acquire) as i64,
        None    => 0,
    }
}

/// Linux `__sys_setuid` (`kernel/sys.c`). With `CAP_SETUID` the real AND
/// saved uid follow; without it the target must already be the real or the
/// SAVED uid — Linux does NOT accept the current effective uid here, which
/// is what keeps a set-uid program from re-acquiring an identity it dropped
/// via `setresuid`.
/// # C: O(1); # Lk: TaskList
pub(crate) fn setuid_on(cur: &Task, uid: u32) -> i64 {
    if !id_valid(uid) { return einval(); }
    let old = triple(cur);
    let new = if cur.has_cap(crate::cap::SETUID) {
        UidTriple { r: uid, e: uid, s: uid }
    } else if uid == old.r || uid == old.s {
        UidTriple { r: old.r, e: uid, s: old.s }
    } else {
        return eperm();
    };
    publish(cur, old, new, uid);
    0
}

/// `sys_setuid(uid)` — slot 105. # C: O(1)
pub fn sys_setuid(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => setuid_on(&c, args.a0 as u32), None => 0 }
}

/// Linux `__sys_setreuid` (`kernel/sys.c`, BSD semantics). The real-uid
/// target is confined to `{ruid, euid}` (NOT the saved uid); the effective
/// target may additionally be the saved uid. The saved uid follows the new
/// effective uid whenever the real uid was set explicitly, or the new
/// effective uid differs from the OLD real uid.
/// # C: O(1); # Lk: TaskList
pub(crate) fn setreuid_on(cur: &Task, ruid: u32, euid: u32) -> i64 {
    let old = triple(cur);
    let privileged = cur.has_cap(crate::cap::SETUID);
    let mut new = old;
    if ruid != ID_UNCHANGED {
        if !privileged && ruid != old.r && ruid != old.e { return eperm(); }
        new.r = ruid;
    }
    if euid != ID_UNCHANGED {
        if !privileged && euid != old.r && euid != old.e && euid != old.s { return eperm(); }
        new.e = euid;
    }
    if ruid != ID_UNCHANGED || (euid != ID_UNCHANGED && euid != old.r) { new.s = new.e; }
    publish(cur, old, new, new.e);
    0
}

/// `sys_setreuid(ruid, euid)` — slot 113. # C: O(1)
pub fn sys_setreuid(args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(c) => setreuid_on(&c, args.a0 as u32, args.a1 as u32),
        None    => 0,
    }
}

/// Linux `__sys_setresuid` (`kernel/sys.c`). Each non-`-1` argument that is
/// not already one of `{ruid, euid, suid}` requires `CAP_SETUID`; the check
/// covers ALL THREE arguments before any is applied, so a partially
/// permitted call changes nothing. `fsuid` is reset to the resulting
/// effective uid even when `euid` was passed as `-1`.
/// # C: O(1); # Lk: TaskList
pub(crate) fn setresuid_on(cur: &Task, ruid: u32, euid: u32, suid: u32) -> i64 {
    let old = triple(cur);
    let old_fsuid = cur.creds.fsuid.load(Ordering::Acquire);
    // Linux's explicit no-op short circuit: nothing observable would change.
    if (ruid == ID_UNCHANGED || ruid == old.r)
        && (euid == ID_UNCHANGED || (euid == old.e && euid == old_fsuid))
        && (suid == ID_UNCHANGED || suid == old.s)
    {
        return 0;
    }
    let introduces = |id: u32| id != ID_UNCHANGED && id != old.r && id != old.e && id != old.s;
    if (introduces(ruid) || introduces(euid) || introduces(suid))
        && !cur.has_cap(crate::cap::SETUID)
    {
        return eperm();
    }
    let new = UidTriple {
        r: if ruid != ID_UNCHANGED { ruid } else { old.r },
        e: if euid != ID_UNCHANGED { euid } else { old.e },
        s: if suid != ID_UNCHANGED { suid } else { old.s },
    };
    publish(cur, old, new, new.e);
    0
}

/// `sys_setresuid(ruid, euid, suid)` — slot 117. # C: O(1)
pub fn sys_setresuid(args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(c) => setresuid_on(&c, args.a0 as u32, args.a1 as u32, args.a2 as u32),
        None    => 0,
    }
}
