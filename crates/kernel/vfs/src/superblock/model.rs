extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64};
use sync::{RwLock, Spinlock};
use crate::dentry::Dentry;
use crate::fs::FileSystem;
use crate::inode::InodeRef;
use super::{FileSystemType, FsBackedSuperOps, FsBackedType, NullFs, SuperBlock, SuperOps, MAX_LFS_FILESIZE, SB_ACTIVE, SB_BORN, SB_UNFROZEN, TIME64_MAX, TIME64_MIN};

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
        Arc::new(Self {
            s_op, s_type, s_magic, s_dev, s_blocksize,
            s_flags: AtomicU64::new(SB_ACTIVE | SB_BORN),
            s_active: AtomicU32::new(1),
            s_count: AtomicU32::new(1),
            s_maxbytes: MAX_LFS_FILESIZE,
            s_time_gran: AtomicU32::new(1),
            s_time_min: AtomicI64::new(TIME64_MIN),
            s_time_max: AtomicI64::new(TIME64_MAX),
            s_writers_frozen: AtomicU32::new(SB_UNFROZEN),
            s_writers_count: AtomicU32::new(0),
            s_id,
            s_uuid: Spinlock::new(([0u8; 16], 0)),
            s_root: RwLock::new(None),
            s_fs_info: Spinlock::new(s_fs_info),
            s_fs: Arc::new(NullFs),
            icache: Spinlock::new(BTreeMap::new()),
            s_wb: Spinlock::new(BTreeMap::new()),
        })
    }

    /// `fill_super` for a legacy `Arc<dyn FileSystem>` backend: build a fresh
    /// superblock whose `s_op`/`s_type` adapt the backend, `s_magic` is
    /// `fs.magic()`, `s_dev` is the per-instance anon dev, and whose `s_root`
    /// dentry is installed over `root_inode` (the bind/whole-fs root). Every
    /// production mount is allocated here (Linux `mount_bdev`/`mount_nodev`).
    /// # C: O(1)
    pub fn for_backend(
        fs: Arc<dyn FileSystem>,
        root_inode: Option<InodeRef>,
        s_dev: u64,
        s_id: String,
    ) -> Arc<Self> {
        // `fill_super` installs the backend's own `super_operations` when it
        // publishes one (ext4 → live on-disk block/inode accounting); else the
        // generic adapter reporting `f_type`/`f_bsize` only.
        let s_op: Arc<dyn SuperOps> = fs.super_ops()
            .unwrap_or_else(|| Arc::new(FsBackedSuperOps { fs: fs.clone() }));
        let s_type: Arc<dyn FileSystemType> = Arc::new(FsBackedType { fs: fs.clone() });
        let s_magic = fs.magic();
        let s_blocksize = fs.block_size();
        let sb = Arc::new(Self {
            s_op, s_type, s_magic, s_dev, s_blocksize,
            s_flags: AtomicU64::new(SB_ACTIVE | SB_BORN),
            s_active: AtomicU32::new(1),
            s_count: AtomicU32::new(1),
            s_maxbytes: MAX_LFS_FILESIZE,
            s_time_gran: AtomicU32::new(1),
            s_time_min: AtomicI64::new(TIME64_MIN),
            s_time_max: AtomicI64::new(TIME64_MAX),
            s_writers_frozen: AtomicU32::new(SB_UNFROZEN),
            s_writers_count: AtomicU32::new(0),
            s_id,
            s_uuid: Spinlock::new(([0u8; 16], 0)),
            s_root: RwLock::new(None),
            s_fs_info: Spinlock::new(Arc::new(())),
            s_fs: fs,
            icache: Spinlock::new(BTreeMap::new()),
            s_wb: Spinlock::new(BTreeMap::new()),
        });
        // `fill_super`: back-stamp the SB into the backend's per-mount state
        // BEFORE building the root dentry, so the root inode's `i_sb()` (and
        // every inode the backend builds afterwards) resolves to this SB.
        sb.s_fs.set_sb(Arc::downgrade(&sb));
        if let Some(i) = root_inode { crate::dcache::d_make_root(i, &sb); }
        sb
    }

    /// The backend (Linux: the SB's write/inode-op carrier). # C: O(1)
    pub fn fs(&self) -> &Arc<dyn FileSystem> { &self.s_fs }

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
    /// `for_backend` seeds. # C: O(1)
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
