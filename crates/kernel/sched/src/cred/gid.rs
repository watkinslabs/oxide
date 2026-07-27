// Linux `kernel/sys.c` gid-family work fns: `__sys_setgid`, `__sys_setregid`,
// `__sys_setresgid`, plus the trivial getters.
//
// commoncap installs NO `task_fix_setgid` hook (only the optional safesetid
// LSM does), so a gid transition never juggles capabilities — it only runs
// the `commit_creds` dumpability block.

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::Task;
use super::commit::{commit_creds, CredIdentity};
use super::limits::{id_valid, ID_UNCHANGED};

/// # C: O(1)
fn eperm() -> i64 { -(Errno::Eperm.as_i32() as i64) }
/// # C: O(1)
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// A task's `(rgid, egid, sgid)`.
#[derive(Clone, Copy)]
struct GidTriple { r: u32, e: u32, s: u32 }

/// # C: O(1)
fn triple(cur: &Task) -> GidTriple {
    GidTriple {
        r: cur.creds.rgid.load(Ordering::Acquire),
        e: cur.creds.egid.load(Ordering::Acquire),
        s: cur.creds.sgid.load(Ordering::Acquire),
    }
}

/// # C: O(1); # Lk: TaskList
fn publish(cur: &Task, new: GidTriple, fsgid: u32) {
    let identity = CredIdentity::capture(cur);
    cur.creds.rgid.store(new.r, Ordering::Release);
    cur.creds.egid.store(new.e, Ordering::Release);
    cur.creds.sgid.store(new.s, Ordering::Release);
    cur.creds.fsgid.store(fsgid, Ordering::Release);
    commit_creds(cur, identity);
}

/// `sys_getgid` — slot 104. Returns the real gid. # C: O(1)
pub fn sys_getgid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => t.creds.rgid.load(Ordering::Acquire) as i64,
        None    => 0,
    }
}

/// `sys_getegid` — slot 108. Returns the effective gid. # C: O(1)
pub fn sys_getegid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => t.creds.egid.load(Ordering::Acquire) as i64,
        None    => 0,
    }
}

/// Linux `__sys_setgid`. Unprivileged targets are confined to the real or
/// SAVED gid (the effective gid is deliberately not accepted).
/// # C: O(1); # Lk: TaskList
pub(crate) fn setgid_on(cur: &Task, gid: u32) -> i64 {
    if !id_valid(gid) { return einval(); }
    let old = triple(cur);
    let new = if cur.has_cap(crate::cap::SETGID) {
        GidTriple { r: gid, e: gid, s: gid }
    } else if gid == old.r || gid == old.s {
        GidTriple { r: old.r, e: gid, s: old.s }
    } else {
        return eperm();
    };
    publish(cur, new, gid);
    0
}

/// `sys_setgid(gid)` — slot 106. # C: O(1)
pub fn sys_setgid(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => setgid_on(&c, args.a0 as u32), None => 0 }
}

/// Linux `__sys_setregid`. Real-gid target confined to `{rgid, egid}`;
/// effective-gid target may additionally be the saved gid.
/// # C: O(1); # Lk: TaskList
pub(crate) fn setregid_on(cur: &Task, rgid: u32, egid: u32) -> i64 {
    let old = triple(cur);
    let privileged = cur.has_cap(crate::cap::SETGID);
    let mut new = old;
    if rgid != ID_UNCHANGED {
        if !privileged && rgid != old.r && rgid != old.e { return eperm(); }
        new.r = rgid;
    }
    if egid != ID_UNCHANGED {
        if !privileged && egid != old.r && egid != old.e && egid != old.s { return eperm(); }
        new.e = egid;
    }
    if rgid != ID_UNCHANGED || (egid != ID_UNCHANGED && egid != old.r) { new.s = new.e; }
    publish(cur, new, new.e);
    0
}

/// `sys_setregid(rgid, egid)` — slot 114. # C: O(1)
pub fn sys_setregid(args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(c) => setregid_on(&c, args.a0 as u32, args.a1 as u32),
        None    => 0,
    }
}

/// Linux `__sys_setresgid`. Same all-three-arguments permission gate as
/// `setresuid`, and `fsgid` follows the resulting effective gid even when
/// `egid` was passed as `-1`.
/// # C: O(1); # Lk: TaskList
pub(crate) fn setresgid_on(cur: &Task, rgid: u32, egid: u32, sgid: u32) -> i64 {
    let old = triple(cur);
    let old_fsgid = cur.creds.fsgid.load(Ordering::Acquire);
    if (rgid == ID_UNCHANGED || rgid == old.r)
        && (egid == ID_UNCHANGED || (egid == old.e && egid == old_fsgid))
        && (sgid == ID_UNCHANGED || sgid == old.s)
    {
        return 0;
    }
    let introduces = |id: u32| id != ID_UNCHANGED && id != old.r && id != old.e && id != old.s;
    if (introduces(rgid) || introduces(egid) || introduces(sgid))
        && !cur.has_cap(crate::cap::SETGID)
    {
        return eperm();
    }
    let new = GidTriple {
        r: if rgid != ID_UNCHANGED { rgid } else { old.r },
        e: if egid != ID_UNCHANGED { egid } else { old.e },
        s: if sgid != ID_UNCHANGED { sgid } else { old.s },
    };
    publish(cur, new, new.e);
    0
}

/// `sys_setresgid(rgid, egid, sgid)` — slot 119. # C: O(1)
pub fn sys_setresgid(args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(c) => setresgid_on(&c, args.a0 as u32, args.a1 as u32, args.a2 as u32),
        None    => 0,
    }
}
