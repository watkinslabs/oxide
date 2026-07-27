// Linux `kernel/groups.c`: `SYSCALL_DEFINE2(getgroups)` /
// `SYSCALL_DEFINE2(setgroups)` plus `may_setgroups`.
//
// Error ORDER is part of the contract and is exercised by the hosted tests:
//   getgroups: EINVAL(size<0) -> return-count(size==0) -> EINVAL(size<ngroups)
//              -> EFAULT(copy).
//   setgroups: EPERM(policy) -> EINVAL(size>NGROUPS_MAX) -> ENOMEM
//              -> per-element EFAULT/EINVAL, left to right.
// `setgroups` sorts ASCENDING before installing (Linux `groups_sort`), which
// is why `getgroups` hands back a sorted list and `groups_search` may binary
// search it.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::Task;
use crate::Creds;
use super::limits::{gidsetsize, id_valid};

/// # C: O(1)
fn eperm() -> i64 { -(Errno::Eperm.as_i32() as i64) }
/// # C: O(1)
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
/// # C: O(1)
fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
/// # C: O(1)
fn enomem() -> i64 { -(Errno::Enomem.as_i32() as i64) }

/// Bytes per `gid_t` in the user array. # C: O(1)
const GID_SIZE: usize = core::mem::size_of::<u32>();

/// Linux `may_setgroups()`: `CAP_SETGID` in the task's user namespace AND a
/// `setgroups` policy that has not been closed by a `/proc/PID/setgroups`
/// write of `deny` (CVE-2014-8989 — a user namespace that dropped groups to
/// gain access must not get them back).
/// # C: O(1); # Lk: Namespace
pub(crate) fn may_setgroups(cur: &Task) -> bool {
    if !cur.has_cap(crate::cap::SETGID) { return false; }
    let Some(owner) = cur.namespace_owner(namespace_identity::NamespaceKind::User) else {
        return true;
    };
    !matches!(user_namespace::setgroups_policy(&owner),
        Ok(user_namespace::SetgroupsPolicy::Deny))
}

/// Linux `SYSCALL_DEFINE2(getgroups, int gidsetsize, gid_t __user *)`.
/// `size == 0` is a pure query: it returns the count and never inspects the
/// pointer, so `getgroups(0, NULL)` succeeds. A too-small non-zero size is
/// `EINVAL` and is reported BEFORE any user access is attempted.
/// # C: O(ngroups); # Lk: TaskList
pub(crate) fn getgroups_on(cur: &Task, args: &SyscallArgs) -> i64 {
    let size = gidsetsize(args.a0);
    if size < 0 { return einval(); }
    let list = cur.creds.group_list();
    let groups: &[u32] = list.as_deref().unwrap_or(&[]);
    if size == 0 { return groups.len() as i64; }
    if groups.len() > size as usize { return einval(); }
    // Linux copies element by element; an empty list therefore touches the
    // pointer zero times and cannot fault.
    for (index, gid) in groups.iter().enumerate() {
        let slot = match args.a1.checked_add((index * GID_SIZE) as u64) {
            Some(slot) => slot,
            None => return efault(),
        };
        if uaccess::copy_to_user(slot, &gid.to_ne_bytes()).is_err() { return efault(); }
    }
    groups.len() as i64
}

/// `sys_getgroups(size, list)` — slot 115. # C: O(ngroups)
pub fn sys_getgroups(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => getgroups_on(&c, args), None => 0 }
}

/// Linux `SYSCALL_DEFINE2(setgroups, int gidsetsize, gid_t __user *)`.
/// The privilege gate runs FIRST — an unprivileged caller gets `EPERM` even
/// for an out-of-range size or a bad pointer. The list is built in kernel
/// memory and only installed once every element has been read and validated,
/// so a mid-array fault leaves the previous list intact.
/// # C: O(n log n); # Lk: TaskList
pub(crate) fn setgroups_on(cur: &Task, args: &SyscallArgs) -> i64 {
    if !may_setgroups(cur) { return eperm(); }
    let size = gidsetsize(args.a0);
    if size as u32 as usize > Creds::NGROUPS_MAX { return einval(); }
    let count = size as usize;
    if count == 0 {
        cur.creds.set_group_list(None);
        return 0;
    }
    let mut groups: Vec<u32> = Vec::new();
    if groups.try_reserve(count).is_err() { return enomem(); }
    for index in 0..count {
        let slot = match args.a1.checked_add((index * GID_SIZE) as u64) {
            Some(slot) => slot,
            None => return efault(),
        };
        let mut bytes = [0u8; GID_SIZE];
        if uaccess::copy_from_user(&mut bytes, slot).is_err() { return efault(); }
        let gid = u32::from_ne_bytes(bytes);
        if !id_valid(gid) { return einval(); }
        groups.push(gid);
    }
    groups.sort_unstable();
    cur.creds.set_group_list(Some(Arc::from(groups.as_slice())));
    0
}

/// `sys_setgroups(size, list)` — slot 116. # C: O(n log n)
pub fn sys_setgroups(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => setgroups_on(&c, args), None => 0 }
}
