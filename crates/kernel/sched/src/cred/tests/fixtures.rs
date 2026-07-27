use core::sync::atomic::Ordering;

use crate::task::{SchedClass, Task};
use crate::Creds;
use syscall::errno::Errno;

/// A task holding the full capability set (the boot/root shape).
pub(super) fn privileged() -> Task {
    Task::new(1, "cred-test", SchedClass::Normal { weight: 1024 })
}

/// A task with NO capabilities and the given `(ruid, euid, suid)` /
/// `(rgid, egid, sgid)` identity — the shape every EPERM case needs.
pub(super) fn unprivileged(uids: (u32, u32, u32), gids: (u32, u32, u32)) -> Task {
    let task = privileged();
    drop_caps(&task);
    set_uids(&task, uids);
    set_gids(&task, gids);
    task
}

/// Strip every capability set. # C: O(1)
pub(super) fn drop_caps(task: &Task) {
    task.creds.cap_effective.store(0, Ordering::Release);
    task.creds.cap_permitted.store(0, Ordering::Release);
    task.creds.cap_inheritable.store(0, Ordering::Release);
    task.creds.cap_ambient.store(0, Ordering::Release);
}

/// Grant exactly the listed capabilities in permitted + effective.
pub(super) fn grant_caps(task: &Task, caps: &[u32]) {
    let mask = caps.iter().fold(0u64, |acc, cap| acc | (1u64 << cap));
    task.creds.cap_effective.store(mask, Ordering::Release);
    task.creds.cap_permitted.store(mask, Ordering::Release);
}

/// # C: O(1)
pub(super) fn set_uids(task: &Task, (r, e, s): (u32, u32, u32)) {
    task.creds.ruid.store(r, Ordering::Release);
    task.creds.euid.store(e, Ordering::Release);
    task.creds.suid.store(s, Ordering::Release);
    task.creds.fsuid.store(e, Ordering::Release);
}

/// # C: O(1)
pub(super) fn set_gids(task: &Task, (r, e, s): (u32, u32, u32)) {
    task.creds.rgid.store(r, Ordering::Release);
    task.creds.egid.store(e, Ordering::Release);
    task.creds.sgid.store(s, Ordering::Release);
    task.creds.fsgid.store(e, Ordering::Release);
}

/// `(ruid, euid, suid, fsuid)`. # C: O(1)
pub(super) fn uids(task: &Task) -> (u32, u32, u32, u32) {
    (task.creds.ruid.load(Ordering::Acquire), task.creds.euid.load(Ordering::Acquire),
     task.creds.suid.load(Ordering::Acquire), task.creds.fsuid.load(Ordering::Acquire))
}

/// `(rgid, egid, sgid, fsgid)`. # C: O(1)
pub(super) fn gids(task: &Task) -> (u32, u32, u32, u32) {
    (task.creds.rgid.load(Ordering::Acquire), task.creds.egid.load(Ordering::Acquire),
     task.creds.sgid.load(Ordering::Acquire), task.creds.fsgid.load(Ordering::Acquire))
}

/// Negated errno as a syscall return value. # C: O(1)
pub(super) fn err(errno: Errno) -> i64 { -(errno.as_i32() as i64) }

/// An address that is guaranteed to fail `access_ok` — the kernel half of
/// the address space. # C: O(1)
pub(super) const KERNEL_PTR: u64 = hal::USER_VA_END;

/// Install a supplementary group list directly (bypassing `setgroups`, so a
/// test can seed an unsorted or oversized list). # C: O(n)
pub(super) fn seed_groups(task: &Task, gids: &[u32]) {
    let list = if gids.is_empty() { None } else { Some(alloc::sync::Arc::from(gids)) };
    task.creds.set_group_list(list);
}

/// `NGROUPS_MAX` re-export so the boundary tests read literally. # C: O(1)
pub(super) const NGROUPS_MAX: usize = Creds::NGROUPS_MAX;
