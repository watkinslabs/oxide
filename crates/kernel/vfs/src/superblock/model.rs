extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64};
use sync::{RwLock, Spinlock};
use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::quota::QuotaInfo;
use super::{FileSystemType, SuperBlock, SuperOps, MAX_LFS_FILESIZE, SB_ACTIVE, SB_BORN, SB_UNFROZEN, TIME64_MAX, TIME64_MIN};

impl SuperBlock {
    /// Construct a superblock with no root yet. The backend then builds
    /// the root inode (with `i_sb = sb`) and calls `dcache::d_make_root`,
    /// which installs `s_root`.
    /// # C: O(1)
    pub fn new(
        s_type: Arc<dyn FileSystemType>,
        s_op: Arc<dyn SuperOps>,
        s_magic: u64,
        s_dev: u64,
        s_blocksize: u32,
        s_id: String,
        s_fs_info: Arc<dyn Any + Send + Sync>,
    ) -> Arc<Self> {
        let sb = Arc::new(Self {
            s_op, s_type, s_magic, s_dev, s_blocksize,
            s_user_ns: super::userns::mounting_user_ns(),
            s_flags: AtomicU64::new(SB_ACTIVE | SB_BORN),
            s_iflags: AtomicU64::new(0),
            s_active: AtomicU32::new(1),
            s_count: AtomicU32::new(1),
            s_maxbytes: MAX_LFS_FILESIZE,
            s_max_links: AtomicU32::new(0),
            s_time_gran: AtomicU32::new(1),
            s_time_min: AtomicI64::new(TIME64_MIN),
            s_time_max: AtomicI64::new(TIME64_MAX),
            s_writers_frozen: AtomicU32::new(SB_UNFROZEN),
            s_writers_count: AtomicU32::new(0),
            s_id,
            s_sysfs_name: Spinlock::new(String::new()),
            s_uuid: Spinlock::new(([0u8; 16], 0)),
            s_root: RwLock::new(None),
            s_umount: RwLock::new(()),
            s_fs_info: Spinlock::new(s_fs_info),
            icache: Spinlock::new(BTreeMap::new()),
            s_wb: Spinlock::new(BTreeMap::new()),
            s_dquot: QuotaInfo::new(),
            s_wb_err: crate::errseq::Errseq::new(),
        });
        sb.s_dquot.bind_super(&sb);
        sb
    }

    /// Finish `fill_super` after the backend selected explicit `s_type` and
    /// `s_op`. The root dentry is derived from the supplied root inode; no
    /// backend object is retained behind the live superblock.
    /// # C: O(1)
    pub fn from_ops(
        s_type: Arc<dyn FileSystemType>,
        s_op: Arc<dyn SuperOps>,
        root_inode: Option<InodeRef>,
        s_magic: u64,
        s_dev: u64,
        s_blocksize: u32,
        s_id: String,
        s_fs_info: Arc<dyn Any + Send + Sync>,
    ) -> Arc<Self> {
        let sb = Self::new(s_type, s_op, s_magic, s_dev, s_blocksize, s_id, s_fs_info);
        if let Some(i) = root_inode { crate::dcache::d_make_root(i, &sb); }
        sb
    }

    /// The root dentry of this instance (Linux `sb->s_root`). # C: O(1)
    pub fn s_root(&self) -> Option<Arc<Dentry>> { self.s_root.read().clone() }

    /// Root inode behind `s_root` (Linux `sb->s_root->d_inode`). # C: O(1)
    pub fn s_root_inode(&self) -> Option<InodeRef> {
        self.s_root().and_then(|d| d.inode())
    }

    /// Install `s_root` (called by `d_make_root`). # C: O(1)
    pub fn set_s_root(&self, root: Arc<Dentry>) { *self.s_root.write() = Some(root); }

    /// `s_fs_info` snapshot — the raw backend-private state `Arc` (Linux
    /// `sb->s_fs_info`). Clones the slot so the lock is not held across use;
    /// prefer the typed [`Self::fs_info_as`] when the concrete type is known.
    /// # C: O(1)
    pub fn fs_info(&self) -> Arc<dyn Any + Send + Sync> { self.s_fs_info.lock().clone() }

    /// `sb->s_fs_info = info` (Linux `fill_super`) — install the backend's
    /// per-superblock private state. Typed: a backend passes its concrete
    /// `Arc<Ext4SbInfo>`/`Arc<TmpfsArena>` and reads it back via
    /// [`Self::fs_info_as`], replacing the `Arc::new(())` placeholder
    /// installed at fill-super construction. # C: O(1)
    pub fn set_fs_info<T: Any + Send + Sync>(&self, info: Arc<T>) {
        *self.s_fs_info.lock() = info;
    }

    /// Downcast `s_fs_info` to the backend's concrete state type (Linux casting
    /// `sb->s_fs_info` to its private struct), returning a counted reference.
    /// `None` if the slot holds a different type or the `()` placeholder. Mirrors
    /// `inode.private::<T>()`. # C: O(1)
    pub fn fs_info_as<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.s_fs_info.lock().clone().downcast::<T>().ok()
    }
}
