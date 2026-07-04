extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64};

use sync::{Inode as InodeLockClass, RwLock};

use crate::file_ops::FileOps;
use crate::inode_ops::InodeOps;
use crate::mapping::AddressSpaceOps;
use crate::poll_subs::PollSubscribers;
use crate::superblock::SuperBlock;
use crate::types::Ino;

use super::flags::{FS_APPEND_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, FS_SYNC_FL};

/// `struct inode` reference (Linux `struct inode *`). CONCRETE — one type for
/// every filesystem; behaviour comes from `i_op`/`i_fop`/`i_private`.
pub type InodeRef = Arc<Inode>;

/// memfd file-sealing store carrier.
pub trait SealCarrier: Send + Sync {
    /// The `F_*_SEALS` word (Linux `shmem_inode_info.seals`). # C: O(1)
    fn seal_word(&self) -> &AtomicU32;
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
    pub(super) i_op:           Arc<dyn InodeOps>,
    pub(super) i_fop:          Arc<dyn FileOps>,
    pub(super) i_private:      Arc<dyn Any + Send + Sync>,
    pub(super) poll_subs:      Option<Arc<PollSubscribers>>,
    pub(super) seal_carrier:   Option<Arc<dyn SealCarrier>>,
    pub(super) i_link:         Option<Box<[u8]>>,
    pub(super) i_xattrs:       Option<crate::xattr::SimpleXattrs>,
    pub(super) i_rwsem:        RwLock<(), InodeLockClass>,
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
/// fileattr`). Carries both the legacy `FS_*_FL` word and the `xflags`/projid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FileAttr {
    pub flags:      u32,
    pub fsx_xflags: u32,
    pub fsx_projid: u32,
}

impl FileAttr {
    /// Translate the VFS `i_flags` (`S_*`) word into the `FS_*_FL` view. # C: O(1)
    pub fn from_i_flags(i_flags: u32) -> Self {
        let mut flags = 0;
        if i_flags & super::flags::S_IMMUTABLE != 0 { flags |= FS_IMMUTABLE_FL; }
        if i_flags & super::flags::S_APPEND    != 0 { flags |= FS_APPEND_FL; }
        if i_flags & super::flags::S_NOATIME   != 0 { flags |= FS_NOATIME_FL; }
        if i_flags & super::flags::S_SYNC      != 0 { flags |= FS_SYNC_FL; }
        FileAttr { flags, fsx_xflags: 0, fsx_projid: 0 }
    }
}
