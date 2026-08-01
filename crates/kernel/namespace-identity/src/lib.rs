// Module manifest:
// - identity: namespace kinds, IDs, and immutable Arc-owned identity objects.
// - registry: canonical allocation and active global/kind/direct-owner indexes.
// - pid_numbers: per-PID-namespace number space (allocate/reserve/free).
// - sync: dependency-neutral registry lock.
// - uapi: Linux initial nsfs inode constants.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod identity;
mod pid_numbers;
mod registry;
mod sync;
mod uapi;

pub use identity::{Namespace, NamespaceFinalizer, NamespaceHandle, NamespaceId, NamespaceKind,
    NamespaceRef, NamespacePin, NamespaceWeak, NsId, PidMemfdNoexecError,
    PID_MEMFD_NOEXEC_SCOPE_EXEC, PID_MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED,
    PID_MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL};
pub use pid_numbers::{PidNumberError, PidNumberSpace, PID_MAX_DEFAULT, PID_MAX_LIMIT};
pub use registry::{active_kind_page, active_owner_page, active_page, allocate, allocate_ns_id,
    allocate_nsfs_ino, allocate_inactive, initial, live_snapshot, lookup, lookup_ns_id,
    lookup_nsfs_ino, AllocError};
pub use uapi::{CGROUP_INIT_NSFS_INO, IPC_INIT_NSFS_INO, PID_INIT_NSFS_INO,
    MNT_INIT_NSFS_INO, NET_INIT_NSFS_INO, TIME_INIT_NSFS_INO, USER_INIT_NSFS_INO, UTS_INIT_NSFS_INO,
    CGROUP_INIT_NS_ID, IPC_INIT_NS_ID, MNT_INIT_NS_ID, NET_INIT_NS_ID,
    PID_INIT_NS_ID, TIME_INIT_NS_ID, USER_INIT_NS_ID, UTS_INIT_NS_ID};

#[cfg(test)]
mod tests;
