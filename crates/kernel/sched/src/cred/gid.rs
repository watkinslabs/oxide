// Linux's gid-family work fns: `__sys_setgid`, `__sys_setregid`,
// `__sys_setresgid`, plus the trivial getters.
//
// commoncap installs NO `task_fix_setgid` hook (only the optional safesetid
// LSM does), so a gid transition never juggles capabilities — it only runs
// the `commit_creds` dumpability block.
//
// Arguments are mapped through the caller's user namespace (`make_kgid`)
// before any permission check and results leave through `from_kgid_munged`,
// exactly as in `uid.rs`.

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use user_namespace::IdMapKind;

use crate::Task;
use super::commit::{commit_creds, CredIdentity};
use super::limits::ID_UNCHANGED;
use super::userns;

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

/// Linux `make_kgid(current_user_ns(), id)`. # C: O(extents)
fn kgid(cur: &Task, id: u32) -> Option<u32> { userns::to_host(cur, IdMapKind::Gid, id) }

/// Linux `from_kgid_munged(current_user_ns(), kgid)`. # C: O(extents)
pub(crate) fn gid_out(cur: &Task, host: u32) -> u32 {
    userns::to_ns(cur, IdMapKind::Gid, host)
}

/// Map an argument that also carries the `-1` "leave unchanged" meaning.
/// `Ok(None)` is "unchanged"; `Err(())` is Linux's `!gid_valid(kgid)` EINVAL.
/// # C: O(extents)
fn optional_kgid(cur: &Task, id: u32) -> Result<Option<u32>, ()> {
    if id == ID_UNCHANGED { return Ok(None); }
    kgid(cur, id).map(Some).ok_or(())
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

/// `sys_getgid` — slot 104. Returns the real gid as this task's user
/// namespace numbers it. # C: O(extents)
pub fn sys_getgid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => gid_out(&t, t.creds.rgid.load(Ordering::Acquire)) as i64,
        None    => 0,
    }
}

/// `sys_getegid` — slot 108. Returns the effective gid. # C: O(extents)
pub fn sys_getegid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => gid_out(&t, t.creds.egid.load(Ordering::Acquire)) as i64,
        None    => 0,
    }
}

/// Linux `__sys_setgid`. A gid the caller's user namespace does not map is
/// `EINVAL`. Unprivileged targets are confined to the real or SAVED gid (the
/// effective gid is deliberately not accepted).
/// # C: O(extents); # Lk: TaskList
pub(crate) fn setgid_on(cur: &Task, gid: u32) -> i64 {
    let Some(gid) = kgid(cur, gid) else { return einval(); };
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

/// `sys_setgid(gid)` — slot 106. # C: O(extents)
pub fn sys_setgid(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => setgid_on(&c, args.a0 as u32), None => 0 }
}

/// Linux `__sys_setregid`. Both arguments are mapped and `EINVAL`-checked
/// before either is permission-checked. Real-gid target confined to
/// `{rgid, egid}`; effective-gid target may additionally be the saved gid.
/// # C: O(extents); # Lk: TaskList
pub(crate) fn setregid_on(cur: &Task, rgid: u32, egid: u32) -> i64 {
    let (Ok(kr), Ok(ke)) = (optional_kgid(cur, rgid), optional_kgid(cur, egid))
        else { return einval(); };
    let old = triple(cur);
    let privileged = cur.has_cap(crate::cap::SETGID);
    let mut new = old;
    if let Some(r) = kr {
        if !privileged && r != old.r && r != old.e { return eperm(); }
        new.r = r;
    }
    if let Some(e) = ke {
        if !privileged && e != old.r && e != old.e && e != old.s { return eperm(); }
        new.e = e;
    }
    if kr.is_some() || ke.is_some_and(|e| e != old.r) { new.s = new.e; }
    publish(cur, new, new.e);
    0
}

/// `sys_setregid(rgid, egid)` — slot 114. # C: O(extents)
pub fn sys_setregid(args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(c) => setregid_on(&c, args.a0 as u32, args.a1 as u32),
        None    => 0,
    }
}

/// Linux `__sys_setresgid`. Same all-three-arguments permission gate as
/// `setresuid`, and `fsgid` follows the resulting effective gid even when
/// `egid` was passed as `-1`.
/// # C: O(extents); # Lk: TaskList
pub(crate) fn setresgid_on(cur: &Task, rgid: u32, egid: u32, sgid: u32) -> i64 {
    let (Ok(kr), Ok(ke), Ok(ks)) =
        (optional_kgid(cur, rgid), optional_kgid(cur, egid), optional_kgid(cur, sgid))
        else { return einval(); };
    let old = triple(cur);
    let old_fsgid = cur.creds.fsgid.load(Ordering::Acquire);
    if kr.is_none_or(|r| r == old.r)
        && ke.is_none_or(|e| e == old.e && e == old_fsgid)
        && ks.is_none_or(|s| s == old.s)
    {
        return 0;
    }
    let introduces = |id: Option<u32>| id.is_some_and(|v| v != old.r && v != old.e && v != old.s);
    if (introduces(kr) || introduces(ke) || introduces(ks))
        && !cur.has_cap(crate::cap::SETGID)
    {
        return eperm();
    }
    let new = GidTriple { r: kr.unwrap_or(old.r), e: ke.unwrap_or(old.e), s: ks.unwrap_or(old.s) };
    publish(cur, new, new.e);
    0
}

/// `sys_setresgid(rgid, egid, sgid)` — slot 119. # C: O(extents)
pub fn sys_setresgid(args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(c) => setresgid_on(&c, args.a0 as u32, args.a1 as u32, args.a2 as u32),
        None    => 0,
    }
}
