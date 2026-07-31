// Linux `kernel/sys.c` uid-family work fns: `__sys_setuid`, `__sys_setreuid`,
// `__sys_setresuid`, plus the trivial getters.
//
// Every work fn takes `&Task` so the full transition (including the error
// ORDER) is hosted-testable without a live runqueue.
//
// Arguments arrive as namespace-relative ids and are mapped to internal ids
// (`make_kuid`) BEFORE any permission check; results leave through
// `from_kuid_munged`. `super::userns` owns that boundary — the triple stored
// on the task is always internal.

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use user_namespace::IdMapKind;

use crate::Task;
use super::capfix::{task_fix_setuid, UidTriple};
use super::commit::{commit_creds, CredIdentity};
use super::limits::ID_UNCHANGED;
use super::userns;

/// # C: O(1)
fn eperm() -> i64 { -(Errno::Eperm.as_i32() as i64) }
/// # C: O(1)
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// Read the task's internal `(ruid, euid, suid)`. # C: O(1)
fn triple(cur: &Task) -> UidTriple {
    UidTriple {
        r: cur.creds.ruid.load(Ordering::Acquire),
        e: cur.creds.euid.load(Ordering::Acquire),
        s: cur.creds.suid.load(Ordering::Acquire),
    }
}

/// Linux `make_kuid(current_user_ns(), id)`. # C: O(extents)
fn kuid(cur: &Task, id: u32) -> Option<u32> { userns::to_host(cur, IdMapKind::Uid, id) }

/// Linux `from_kuid_munged(current_user_ns(), kuid)`. # C: O(extents)
pub(crate) fn uid_out(cur: &Task, host: u32) -> u32 {
    userns::to_ns(cur, IdMapKind::Uid, host)
}

/// Map an argument that also carries the `-1` "leave unchanged" meaning.
/// `Ok(None)` is "unchanged"; `Err(())` is Linux's `!uid_valid(kuid)` EINVAL.
/// # C: O(extents)
fn optional_kuid(cur: &Task, id: u32) -> Result<Option<u32>, ()> {
    if id == ID_UNCHANGED { return Ok(None); }
    kuid(cur, id).map(Some).ok_or(())
}

/// Publish a uid triple plus the fsuid Linux derives from it, then run the
/// `LSM_SETID_*` capability juggle and the `commit_creds` side effects.
/// # C: O(1); # Lk: TaskList
fn publish(cur: &Task, old: UidTriple, new: UidTriple, fsuid: u32) {
    let identity = CredIdentity::capture(cur);
    let root = userns::root_uid(cur);
    cur.creds.ruid.store(new.r, Ordering::Release);
    cur.creds.euid.store(new.e, Ordering::Release);
    cur.creds.suid.store(new.s, Ordering::Release);
    cur.creds.fsuid.store(fsuid, Ordering::Release);
    task_fix_setuid(cur, old, new, root);
    commit_creds(cur, identity);
}

/// `sys_getuid` — slot 102. Returns the real uid as this task's user
/// namespace numbers it. # C: O(extents)
pub fn sys_getuid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => uid_out(&t, t.creds.ruid.load(Ordering::Acquire)) as i64,
        None    => 0,
    }
}

/// `sys_geteuid` — slot 107. Returns the effective uid. # C: O(extents)
pub fn sys_geteuid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => uid_out(&t, t.creds.euid.load(Ordering::Acquire)) as i64,
        None    => 0,
    }
}

/// Linux `__sys_setuid` (`kernel/sys.c`). An id the caller's user namespace
/// does not map is `EINVAL` before any privilege is considered. With
/// `CAP_SETUID` the real AND saved uid follow; without it the target must
/// already be the real or the SAVED uid — Linux does NOT accept the current
/// effective uid here, which is what keeps a set-uid program from
/// re-acquiring an identity it dropped via `setresuid`.
/// # C: O(extents); # Lk: TaskList
pub(crate) fn setuid_on(cur: &Task, uid: u32) -> i64 {
    let Some(uid) = kuid(cur, uid) else { return einval(); };
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

/// `sys_setuid(uid)` — slot 105. # C: O(extents)
pub fn sys_setuid(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => setuid_on(&c, args.a0 as u32), None => 0 }
}

/// Linux `__sys_setreuid` (`kernel/sys.c`, BSD semantics). BOTH arguments
/// are mapped and validated before either is permission-checked, so an
/// unmapped effective uid is `EINVAL` even when the real uid alone would
/// have been `EPERM`. The real-uid target is confined to `{ruid, euid}` (NOT
/// the saved uid); the effective target may additionally be the saved uid.
/// The saved uid follows the new effective uid whenever the real uid was set
/// explicitly, or the new effective uid differs from the OLD real uid.
/// # C: O(extents); # Lk: TaskList
pub(crate) fn setreuid_on(cur: &Task, ruid: u32, euid: u32) -> i64 {
    let (Ok(kr), Ok(ke)) = (optional_kuid(cur, ruid), optional_kuid(cur, euid))
        else { return einval(); };
    let old = triple(cur);
    let privileged = cur.has_cap(crate::cap::SETUID);
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
    publish(cur, old, new, new.e);
    0
}

/// `sys_setreuid(ruid, euid)` — slot 113. # C: O(extents)
pub fn sys_setreuid(args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(c) => setreuid_on(&c, args.a0 as u32, args.a1 as u32),
        None    => 0,
    }
}

/// Linux `__sys_setresuid` (`kernel/sys.c`). All three arguments are mapped
/// and `EINVAL`-checked first. Each non-`-1` argument that is not already one
/// of `{ruid, euid, suid}` requires `CAP_SETUID`; the check covers ALL THREE
/// before any is applied, so a partially permitted call changes nothing.
/// `fsuid` is reset to the resulting effective uid even when `euid` was
/// passed as `-1`.
/// # C: O(extents); # Lk: TaskList
pub(crate) fn setresuid_on(cur: &Task, ruid: u32, euid: u32, suid: u32) -> i64 {
    let (Ok(kr), Ok(ke), Ok(ks)) =
        (optional_kuid(cur, ruid), optional_kuid(cur, euid), optional_kuid(cur, suid))
        else { return einval(); };
    let old = triple(cur);
    let old_fsuid = cur.creds.fsuid.load(Ordering::Acquire);
    // Linux's explicit no-op short circuit: nothing observable would change.
    if kr.is_none_or(|r| r == old.r)
        && ke.is_none_or(|e| e == old.e && e == old_fsuid)
        && ks.is_none_or(|s| s == old.s)
    {
        return 0;
    }
    let introduces = |id: Option<u32>| id.is_some_and(|v| v != old.r && v != old.e && v != old.s);
    if (introduces(kr) || introduces(ke) || introduces(ks))
        && !cur.has_cap(crate::cap::SETUID)
    {
        return eperm();
    }
    let new = UidTriple {
        r: kr.unwrap_or(old.r), e: ke.unwrap_or(old.e), s: ks.unwrap_or(old.s),
    };
    publish(cur, old, new, new.e);
    0
}

/// `sys_setresuid(ruid, euid, suid)` — slot 117. # C: O(extents)
pub fn sys_setresuid(args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(c) => setresuid_on(&c, args.a0 as u32, args.a1 as u32, args.a2 as u32),
        None    => 0,
    }
}
