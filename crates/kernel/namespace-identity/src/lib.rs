// Module manifest:
// - identity: namespace kinds, IDs, and immutable Arc-owned identity objects.
// - registry: canonical init owners, monotonic allocation, and weak indexes.
// - sync: dependency-neutral registry lock.
// - uapi: Linux initial nsfs inode constants.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod identity;
mod registry;
mod sync;
mod uapi;

pub use identity::{Namespace, NamespaceFinalizer, NamespaceId, NamespaceKind, NamespaceRef, NsId};
pub use registry::{allocate, allocate_ns_id, allocate_nsfs_ino, initial, live_snapshot, lookup,
    lookup_ns_id, lookup_nsfs_ino, AllocError};
pub use uapi::{CGROUP_INIT_NSFS_INO, IPC_INIT_NSFS_INO, PID_INIT_NSFS_INO,
    MNT_INIT_NSFS_INO, TIME_INIT_NSFS_INO, USER_INIT_NSFS_INO, UTS_INIT_NSFS_INO,
    CGROUP_INIT_NS_ID, IPC_INIT_NS_ID, MNT_INIT_NS_ID, NET_INIT_NS_ID,
    PID_INIT_NS_ID, TIME_INIT_NS_ID, USER_INIT_NS_ID, UTS_INIT_NS_ID};

#[cfg(test)]
mod tests;
