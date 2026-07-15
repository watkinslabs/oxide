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

pub use identity::{Namespace, NamespaceId, NamespaceKind, NamespaceRef};
pub use registry::{allocate, allocate_nsfs_ino, initial, live_snapshot, lookup,
    lookup_nsfs_ino, AllocError};
pub use uapi::{CGROUP_INIT_NSFS_INO, IPC_INIT_NSFS_INO, PID_INIT_NSFS_INO,
    MNT_INIT_NSFS_INO, TIME_INIT_NSFS_INO, USER_INIT_NSFS_INO, UTS_INIT_NSFS_INO};

#[cfg(test)]
mod tests;
