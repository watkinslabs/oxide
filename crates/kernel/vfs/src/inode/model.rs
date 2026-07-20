extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64};

use crate::file_ops::FileOps;
use crate::inode_ops::InodeOps;
use crate::mapping::AddressSpaceOps;
use crate::poll_subs::PollSubscribers;
use crate::quota::InodeDquots;
use crate::superblock::SuperBlock;
use crate::types::Ino;

use super::flags::{FS_APPEND_FL, FS_CASEFOLD_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, FS_SYNC_FL};
use super::file_lock::FileLockContext;

/// `struct inode` reference (Linux `struct inode *`). CONCRETE — one type for
/// every filesystem; behaviour comes from `i_op`/`i_fop`/`i_private`.
pub type InodeRef = Arc<Inode>;

/// memfd file-sealing store carrier.
pub trait SealCarrier: Send + Sync {
    /// The `F_*_SEALS` word (Linux `shmem_inode_info.seals`). # C: O(1)
    fn seal_word(&self) -> &AtomicU32;
}

/// Backend write-through for `chown(2)` on a SYNTHESIZED inode whose owner
/// lives in the backing store, not the in-core inode (Linux kernfs persists
/// chown to `kernfs_node->iattr` via `->setattr`; cgroupfs/sysfs re-create the
/// inode on every lookup, so a plain `i_uid`/`i_gid` store would be lost). When
/// present, [`Inode::set_owner`] invokes `persist_owner` so the new uid/gid is
/// recorded in the backend and re-applied on the next synthesis — the mechanism
/// that makes systemd cgroup delegation (chown of the delegated subtree to the
/// target uid) actually take effect. Absent (`None`) on every native-storage
/// inode, so their chown path is byte-for-byte unchanged.
pub trait OwnerPersist: Send + Sync {
    /// Record `(uid, gid)` in the backing store keyed by this inode's identity.
    /// # C: backend-dependent
    fn persist_owner(&self, uid: u32, gid: u32);
}

/// `struct inode` (`16§2`). One per in-core inode; shared by every dentry alias
/// (hardlinks) and every open `File` on it.
pub struct Inode {
    pub(super) i_ino:          Ino,
    pub(super) i_mode:         AtomicU32,
    pub(super) i_size:         AtomicU64,
    pub(super) i_blocks:       AtomicU64,
    pub(super) i_nlink:        AtomicU32,
    pub(super) i_uid:          AtomicU32,
    pub(super) i_gid:          AtomicU32,
    pub(super) i_projid:       AtomicU32,
    pub(super) i_flags:        AtomicU32,
    pub(super) i_rdev:         u32,
    pub(super) i_generation:   u32,
    pub(super) i_atime:        AtomicU64,
    pub(super) i_mtime:        AtomicU64,
    pub(super) i_ctime:        AtomicU64,
    pub(super) i_btime:        u64,
    pub(super) i_state:        AtomicU32,
    pub(super) i_count:        AtomicU32,
    pub(super) i_version:      AtomicU64,
    pub(super) i_fsid:         AtomicU64,
    pub(super) i_sb:           Weak<SuperBlock>,
    pub(super) i_mapping:      Option<Arc<dyn AddressSpaceOps>>,
    /// Canonical `address_space->i_mmap` reverse-map owner. It is inode
    /// lifetime state, so separately opened file descriptors and forked VMAs
    /// cannot invent competing file-rmap objects for the same shared pages.
    pub(super) i_file_rmap:    Arc<vmm::FileRmap>,
    pub(super) i_op:           Arc<dyn InodeOps>,
    pub(super) i_fop:          Arc<dyn FileOps>,
    pub(super) i_private:      Arc<dyn Any + Send + Sync>,
    pub(super) poll_subs:      Option<Arc<PollSubscribers>>,
    pub(super) seal_carrier:   Option<Arc<dyn SealCarrier>>,
    pub(super) owner_persist:  Option<Arc<dyn OwnerPersist>>,
    pub(super) i_link:         Option<Box<[u8]>>,
    pub(super) i_xattrs:       Option<crate::xattr::SimpleXattrs>,
    pub(crate) i_dquot:        InodeDquots,
    pub(super) i_rwsem:        super::rwsem::InodeRwsem,
    /// `inode->i_flctx`: single owner for BSD flock and POSIX/OFD records.
    pub(super) i_flctx:        FileLockContext,
}

/// One physical extent reported by `Inode::fiemap` (Linux `struct
/// fiemap_extent`). Byte offsets/lengths, not blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FiemapExtent {
    pub logical:  u64,
    pub physical: u64,
    pub length:   u64,
    pub flags:    u32,
}

/// Inode attribute view shared by `fileattr_get`/`fileattr_set` (Linux `struct
/// fileattr`). Carries the legacy `FS_*_FL` word and Linux `fsxattr` fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FileAttr {
    pub flags:          u32,
    pub fsx_xflags:     u32,
    pub fsx_extsize:    u32,
    pub fsx_nextents:   u32,
    pub fsx_projid:     u32,
    pub fsx_cowextsize: u32,
}

impl FileAttr {
    /// Translate the VFS `i_flags` (`S_*`) word into the `FS_*_FL` view. # C: O(1)
    pub fn from_i_flags(i_flags: u32) -> Self {
        let mut flags = 0;
        if i_flags & super::flags::S_IMMUTABLE != 0 { flags |= FS_IMMUTABLE_FL; }
        if i_flags & super::flags::S_APPEND    != 0 { flags |= FS_APPEND_FL; }
        if i_flags & super::flags::S_NOATIME   != 0 { flags |= FS_NOATIME_FL; }
        if i_flags & super::flags::S_SYNC      != 0 { flags |= FS_SYNC_FL; }
        if i_flags & super::flags::S_CASEFOLD  != 0 { flags |= FS_CASEFOLD_FL; }
        FileAttr { flags, ..Default::default() }
    }
}
