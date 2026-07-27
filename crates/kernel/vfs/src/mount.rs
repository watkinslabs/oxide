//! Mount tree per `docs/16§6`, structured like Linux's `struct mount`.
//!
//! Module manifest:
//! - `flags`: per-mount `MNT_*` option bits plus mount(2) `MS_*` request flags.
//! - `graph`: dentry identity, mount-hash, path rendering, and lookup helpers.
//! - `model`: propagation enum, `Mount`, global mount table, and mount accessors.
//! - `attach`: superblock materialization plus root/submount registration.
//! - `clone_tree`: open_tree/bind clone construction and recursive graft commit.
//! - `recursive`: recursive attach and mount-subtree predicates.
//! - `namespace`: pivot/bind/move namespace-tree mutations.
//! - `namespace_lifecycle`: mount refcount, namespace copy, and namespace reap.
//! - `attrs`: remount, mount_setattr, write pins, and inode lookup helpers.
//! - `propagation`: peer/slave propagation fan-out.
//! - `detach`: umount/detach tear-down.
//! - `pivot_check`: `pivot_root(2)` admission ladder and its errno order.
//! - `mnt_flags`: internal lifecycle flags and mount_setattr translation.
//! - `expiry`: expiry list marking and sweep logic.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};
use sync::{MountTable as MountClass, MountWrite as MountWriteClass, Spinlock};

use crate::dentry::Dentry;
use crate::fs::{superblock_from_filesystem, FileSystem, KResult};
use crate::inode::InodeRef;
use crate::mntns::{self, get_mountpoint, put_mountpoint, Mountpoint};
use crate::superblock::{FileSystemType, SuperBlock};
use crate::types::VfsError;

// Re-export the namespace / notify / hook surface so callers keep using
// `vfs::mount::*` (provider install, generation poll, chroot hook, reap).
pub use crate::mntns::{
    chroot_fs_refs, current_namespace, current_ns, current_ns_owner, mount_generation,
    mountinfo_poll_mask, mountinfo_poll_mask_ns, set_chroot_refs_hook, set_current_ns_provider,
    ChrootRefsHook, MntNamespace, Mountpoint as MountpointObj, NsProvider,
};

// Mount-propagation engine (peer/slave fan-out) lives in a submodule to hold
// the line cap; its public surface stays `vfs::mount::*` verbatim.
mod propagation;
pub use propagation::{join_peer_group, peer_group_of, propagate_mount, set_propagation, set_propagation_recursive};

// Umount / detach tear-down (umount(2), d_invalidate detach, propagate_umount)
// lives in a submodule to hold the line cap; public surface stays `vfs::mount::*`.
mod detach;
pub use detach::{mountpoint_dentry_of, unregister, unregister_top};

// pivot_root(2)'s admission ladder — `path_pivot_root()`'s check order, whose
// sequence is the only observable part of a rejected call. A submodule (not an
// `include!`) so it carries its own hosted unit tests.
mod pivot_check;
pub use pivot_check::{pivot_check, PivotFacts};
pub(crate) use detach::detach_mounts_on;

// mnt_flags model: the kernel-internal `mnt_flags` bit set (MNT_LOCKED /
// MNT_INTERNAL / MNT_DOOMED / …, Linux `include/linux/mount.h`) distinct from
// the MS_*-valued option mask, plus typed option-mask + atime-policy readback.
mod mnt_flags;
pub use mnt_flags::{
    AtimePolicy, MNT_DOOMED, MNT_EXPIRE_MARK, MNT_INTERNAL, MNT_LOCKED, MNT_MARKED, MNT_UMOUNT,
    MNT_ATIME_MASK, MOUNT_ATTR_IDMAP, MOUNT_ATTR_NOATIME, MOUNT_ATTR_RDONLY, MOUNT_ATTR_SETTABLE,
    MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME, mount_attr_to_mnt,
};

// Mount expiry list (Linux `mark_mounts_for_expiry`, autofs/NFS auto-umount):
// a two-sweep grace where an unused, unmarked mount is marked on one pass and
// reaped on the next if still idle.
mod expiry;
pub use expiry::{
    expire_list_create, mark_mounts_for_expiry, mnt_expire_add, mnt_expire_remove,
    sweep_expired_mounts,
};

mod flags;
pub use flags::*;

mod render;
pub use render::{
    mountinfo_mount_options, mountinfo_optional_fields, mountinfo_root_field,
    mountinfo_source_field, mountinfo_super_options, render_mount_root_field,
};

include!("mount/graph.rs");
include!("mount/model.rs");
include!("mount/attach.rs");
include!("mount/clone_tree.rs");
include!("mount/recursive.rs");
include!("mount/namespace.rs");
include!("mount/namespace_lifecycle.rs");
include!("mount/attrs.rs");
