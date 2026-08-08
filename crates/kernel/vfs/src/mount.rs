//! Mount tree per `docs/16§6`, structured like Linux's `struct mount`.
//!
//! Module manifest:
//! - `flags`: per-mount `MNT_*` option bits plus mount(2) `MS_*` request flags.
//! - `graph`: dentry identity, mount-hash, path rendering, and lookup helpers.
//! - `model`: propagation enum, `Mount`, global mount table, and mount accessors.
//! - `attach`: superblock materialization plus root/submount registration.
//! - `clone_tree`: open_tree/bind clone construction and recursive graft commit.
//! - `recursive`: recursive attach and mount-subtree predicates.
//! - `new_namespace`: the namespace form of fsmount/open_tree — one constructor.
//! - `namespace`: bind/move namespace-tree mutations and the pivot retree commit.
//! - `pivot`: `pivot_root(2)` tree surgery — slot swap, re-root, re-render.
//! - `namespace_lifecycle`: mount refcount, namespace copy, and namespace reap.
//! - `attrs`: remount, mount_setattr, write pins, and inode lookup helpers.
//! - `beneath`: `move_mount(MOVE_MOUNT_BENEATH)` slot swap + its admission ladder.
//! - `propagation`: peer/slave propagation fan-out.
//! - `detach`: umount/detach tear-down.
//! - `pivot_check`: `pivot_root(2)` admission ladder and its errno order.
//! - `mnt_flags`: internal lifecycle flags and mount_setattr translation.
//! - `locked`: MNT_LOCK_*/MNT_LOCKED stamping and the no-relax admission ladder.
//! - `revealing`: `mount_too_revealing` — the userns already-visible constraint.
//! - `expiry`: expiry list marking and sweep logic.
//! - `busy`: the propagation-aware `umount(2)` busy test.
//! - `shrink`: eager reap of expirable submounts under an unmount target.

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
mod anon;
pub use anon::{anon_ns_root, create_anon_mount, create_ns_mount, dissolve_anon, graft_anon_mount_at};

// The namespace form of `fsmount(2)` and `open_tree(2)`: ONE constructor for the
// namespace both build, so the root-copy / placement / propagation / freezing
// shape exists exactly once.
mod new_namespace;
pub use new_namespace::{create_new_namespace, NsMountSource};

mod propagation;
pub use propagation::{change_type_by_id, join_peer_group, peer_group_of, propagate_mount, set_group,
    set_propagation, set_propagation_recursive};

// `do_change_type`'s admission ladder as a pure decision over sampled facts —
// a submodule (not an `include!`) so it carries its own hosted unit tests.
mod propagation_check;
pub use propagation_check::{change_type_check, flags_to_propagation_type, ChangeType,
    ChangeTypeFacts};

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
    MNT_LOCK_ATIME, MNT_LOCK_MASK, MNT_LOCK_NODEV, MNT_LOCK_NOEXEC, MNT_LOCK_NOSUID,
    MNT_LOCK_READONLY,
    MOUNT_ATTR_IDMAP, MOUNT_ATTR_NOATIME, MOUNT_ATTR_RDONLY, MOUNT_ATTR_SETTABLE,
    MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME, mount_attr_to_mnt,
    MOUNT_ATTR_NODEV, MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID,
    MOUNT_ATTR_NOSYMFOLLOW,
    MNT_DETACH, MNT_EXPIRE, MNT_FORCE, UMOUNT_NOFOLLOW, UMOUNT_VALID,
};

// umount2(2)'s admission ladder as a pure decision over sampled facts, so its
// ORDER (and MNT_EXPIRE's two-pass EAGAIN grace) is a hosted unit test.
mod umount_check;
pub use umount_check::{umount_check, umount_facts, Umount, UmountFacts, UmountPlan, UmountRefusal, EXPIRE_REQUIRED_REFS};

// `propagate_mount_busy`: the propagation-aware busy test both `umount(2)` and
// the expiry sweep apply — a peer/slave copy of the mount being pinned refuses
// the unmount just as a pin on the named mount does. A submodule so the rule
// (including the completely-overmounted-mirror exception) carries its own
// hosted unit tests.
mod busy;
pub use busy::{propagate_busy_decision, propagate_mount_busy, BusyFacts, MirrorBusyFacts,
    PASSIVE_REFCNT, UMOUNT_SYSCALL_REFCNT};

// `shrink_submounts`: the eager reap of expirable (automounted) submounts a
// non-lazy `umount(2)` owes its target before the busy test runs.
mod shrink;
pub use shrink::shrink_submounts;

// Locked mount flags: the MNT_LOCK_*/MNT_LOCKED stamp an unprivileged user-ns
// copy inherits (`lock_mnt_tree`) and the ladder that refuses to relax it
// (`can_change_locked_flags`). A submodule so it carries its own unit tests.
mod locked;
pub use locked::{
    can_change_locked_flags, can_change_locked_options, has_locked_children, lock_bits_for,
    lock_detached_tree,
};

// Idmapped mount installation is one VFS transaction over detached mount
// state, shared by open_tree and the deferred fsmount representation.
mod idmapped;
pub use idmapped::{can_idmap_mount, can_idmap_superblock, idmap_facts_for, IdmapFacts,
    IdmapSet, mnt_setattr_attached, mnt_setattr_detached_tree};

// mount_too_revealing: the visibility constraint on an unprivileged user-ns
// mount of a FS_USERNS_MOUNT_RESTRICTED filesystem (procfs/sysfs). A submodule
// so it carries its own unit tests.
mod revealing;
pub use revealing::{mnt_already_visible, mount_too_revealing};

// Mount-tree change notification (`fsnotify_mnt_attach`/`_detach`/`_move`): the
// settable hook plus the attach/detach/move classification. The notification
// subsystem installs the implementation, so vfs never depends on it.
mod notify;
pub use notify::{mnt_transition_mask, set_mnt_notify_hook, MntNotifyHook,
    FS_MNT_ATTACH, FS_MNT_DETACH, FS_MNT_MOVE};

// Mount expiry list (Linux `mark_mounts_for_expiry`, autofs/NFS auto-umount):
// a two-sweep grace where an unused, unmarked mount is marked on one pass and
// reaped on the next if still idle.
mod expiry;
pub use expiry::{
    expire_list_create, mark_mounts_for_expiry, mnt_expire_add, mnt_expire_remove,
    sweep_expired_mounts,
};
use expiry::mnt_expire_remove_any;

// `is_path_reachable`: the single "is this path at or below that root?"
// predicate shared by pivot_root's two rungs and the statmount/listmount
// visibility gates.
mod reachable;
pub use reachable::{mount_reachable_from, path_reachable_from_root, reachable_from_mount_root};

// statmount(2)/listmount(2) fact gathering: the unique-mount-id space, the
// per-mount reportable values, and the listmount subtree selection.
mod statmount;
pub use statmount::{dominating_group_id, is_slave, listmount_ids, master_group_id,
    mounts_in_ns_snapshot,
    mnt_id_from_unique, mnt_to_attr_flags, mnt_to_propagation_flags, mount_by_unique_id_in_ns,
    statmount_facts, unique_mnt_id, MountFacts, MNT_UNIQUE_ID_OFFSET};

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
include!("mount/pivot.rs");
include!("mount/namespace_lifecycle.rs");
include!("mount/attrs.rs");
include!("mount/beneath.rs");
