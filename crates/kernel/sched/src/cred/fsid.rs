// Linux `__sys_setfsuid` / `__sys_setfsgid` (`kernel/sys.c`).
//
// Neither can fail: EVERY path returns the PREVIOUS fsuid/fsgid, whether the
// change was applied, rejected for lack of privilege, or skipped because the
// argument was the invalid id `(uid_t)-1`. A caller detects rejection by
// calling twice, never by an errno.
//
// The argument is mapped through the caller's user namespace (`make_kuid`);
// an id the namespace does not map is treated exactly like `(uid_t)-1` — no
// change, previous id returned. The RETURNED id is the previous fsuid as
// that namespace numbers it (`from_kuid_munged`), not the internal one.

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use user_namespace::IdMapKind;

use crate::Task;
use super::capfix::task_fix_setfsuid;
use super::commit::{commit_creds, CredIdentity};
use super::userns;

/// Linux `__sys_setfsuid`. Permitted when the target is already one of
/// `{ruid, euid, suid, fsuid}` or the task holds `CAP_SETUID`; an accepted
/// change runs the `LSM_SETID_FS` capability juggle.
/// # C: O(extents); # Lk: TaskList
pub(crate) fn setfsuid_on(cur: &Task, uid: u32) -> i64 {
    let previous = cur.creds.fsuid.load(Ordering::Acquire);
    let reported = userns::to_ns(cur, IdMapKind::Uid, previous) as i64;
    let Some(uid) = userns::to_host(cur, IdMapKind::Uid, uid) else { return reported; };
    let allowed = uid == cur.creds.ruid.load(Ordering::Acquire)
        || uid == cur.creds.euid.load(Ordering::Acquire)
        || uid == cur.creds.suid.load(Ordering::Acquire)
        || uid == previous
        || cur.has_cap(crate::cap::SETUID);
    if allowed && uid != previous {
        let identity = CredIdentity::capture(cur);
        let root = userns::root_uid(cur);
        cur.creds.fsuid.store(uid, Ordering::Release);
        task_fix_setfsuid(cur, previous, uid, root);
        commit_creds(cur, identity);
    }
    reported
}

/// `sys_setfsuid(uid)` — slot 122. # C: O(extents)
pub fn sys_setfsuid(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => setfsuid_on(&c, args.a0 as u32), None => 0 }
}

/// Linux `__sys_setfsgid`. Mirrors `setfsuid` over the gid triple; commoncap
/// installs no gid hook, so no capability juggle runs here.
/// # C: O(extents); # Lk: TaskList
pub(crate) fn setfsgid_on(cur: &Task, gid: u32) -> i64 {
    let previous = cur.creds.fsgid.load(Ordering::Acquire);
    let reported = userns::to_ns(cur, IdMapKind::Gid, previous) as i64;
    let Some(gid) = userns::to_host(cur, IdMapKind::Gid, gid) else { return reported; };
    let allowed = gid == cur.creds.rgid.load(Ordering::Acquire)
        || gid == cur.creds.egid.load(Ordering::Acquire)
        || gid == cur.creds.sgid.load(Ordering::Acquire)
        || gid == previous
        || cur.has_cap(crate::cap::SETGID);
    if allowed && gid != previous {
        let identity = CredIdentity::capture(cur);
        cur.creds.fsgid.store(gid, Ordering::Release);
        commit_creds(cur, identity);
    }
    reported
}

/// `sys_setfsgid(gid)` — slot 123. # C: O(extents)
pub fn sys_setfsgid(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => setfsgid_on(&c, args.a0 as u32), None => 0 }
}
