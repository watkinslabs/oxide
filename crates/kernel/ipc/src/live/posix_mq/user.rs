// User-memory access and current-task snapshots shared by the mqueue slots.
// Kept out of the slot bodies so each of them reads as the Linux function it
// mirrors (`docs/53`).

use core::sync::atomic::Ordering;

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

/// Negative-errno syscall return. # C: O(1)
pub fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux `current_cred()` for the VFS DAC checks; the snapshot layout is
/// owned by `sched::Creds::to_vfs_cred`. # C: O(1)
pub fn current_cred() -> vfs::Cred {
    let Some(c) = sched::current() else { return vfs::Cred::root(); };
    let effective = c.creds.cap_effective.load(Ordering::Acquire);
    c.creds.to_vfs_cred(c.creds.fsuid.load(Ordering::Acquire),
                        c.creds.fsgid.load(Ordering::Acquire), effective)
}

/// The caller's IPC namespace — Linux `current->nsproxy->ipc_ns`, which is
/// what makes a queue name private to that namespace. # C: O(1)
pub fn ipc_ns() -> Result<NamespaceId, Errno> {
    crate::ipc_namespace::current().map(|o| o.key()).map_err(|_| Errno::Einval)
}

/// Linux `task_tgid(current)` — mq notifications are per-PROCESS. # C: O(1)
pub fn current_tgid() -> Option<u32> {
    sched::live::current().map(|c| c.tgid.load(Ordering::Acquire))
}

// User memory is reached through `crate::useraccess`, the crate's one
// non-gated owner of the exception-table copies. These helpers used to
// range-check an address and then dereference it, which proves the number is
// inside the user half and nothing about a page being under it.
pub use crate::useraccess::{
    read_i32 as read_user_i32, read_i64 as read_user_i64, read_bytes as read_user_bytes,
    write_bytes as write_user_bytes, write_i64 as write_user_i64, write_u32 as write_user_u32,
};
