// `struct super_block` per `16§2` — ONE per mounted filesystem instance.
//
// Linux object model (include/linux/fs.h): a superblock owns the root
// DENTRY (`s_root`), the super_operations vtable (`s_op`), the
// file_system_type backref (`s_type`), the on-disk identity
// (`s_magic`/`s_dev`/`s_blocksize`/`s_id`), backend-private state
// (`s_fs_info`), and the per-instance inode cache (iget/ilookup/iput).
//
// CYCLE NOTE: `s_root: Arc<Dentry>` is a STRONG owning ref; `Dentry::sb`
// is `Weak<SuperBlock>` (Linux `d_sb` is non-owning). The mount table
// owns the `Arc<SuperBlock>` strong ref. Umount = `put_super()` then
// clear `s_root` → the dentry tree drops, breaking what would otherwise
// be an Arc cycle.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{RwLock, Spinlock, Superblock as SbClass};

use crate::dentry::Dentry;
use crate::fs::FileSystem;
use crate::inode::{Inode, InodeRef};
use crate::types::{Ino, KResult};

/// `get_anon_bdev` (Linux `fs/super.c`) — per-instance anonymous block-dev
/// id source for filesystems with no real backing device. Each mounted
/// instance gets a distinct `s_dev` so two `mount -t tmpfs` report
/// different `st_dev` (the thing a per-fs-type constant cannot express).
/// Starts above the legacy `dev_t` minor range to avoid colliding with a
/// real block device's packed `(major<<20)|minor`. # C: O(1)
static NEXT_ANON_DEV: AtomicU64 = AtomicU64::new(0x0000_0001_0000_0000);

/// Allocate a fresh anonymous device id (`get_anon_bdev`). # C: O(1)
pub fn next_anon_dev() -> u64 { NEXT_ANON_DEV.fetch_add(1, Ordering::Relaxed) }

/// Placeholder backend for an `s_fs`-less superblock built via
/// [`SuperBlock::new`] (the object-model unit tests). Production superblocks
/// are built via [`SuperBlock::for_backend`] and carry their real backend.
struct NullFs;
impl FileSystem for NullFs {
    fn name(&self) -> &str { "none" }
}

/// Adapter exposing a legacy `Arc<dyn FileSystem>` as `super_operations`
/// (`s_op`). `statfs` reports the backend `magic` as `f_type`; the inode
/// `SuperBlock::statfs` then defaults `f_bsize` from `s_blocksize`. This is
/// the generic `fill_super` glue so every backend gets a working superblock
/// without a per-fs `SuperOps` impl (richer per-fs `SuperOps` layer on top).
struct FsBackedSuperOps { fs: Arc<dyn FileSystem> }
impl SuperOps for FsBackedSuperOps {
    fn statfs(&self) -> KResult<SbStatFs> {
        Ok(SbStatFs { f_type: self.fs.magic(), f_bsize: 4096, ..Default::default() })
    }
}

/// Adapter exposing a legacy `Arc<dyn FileSystem>` as `file_system_type`
/// (`s_type`). `mount` is `fill_super`: build a fresh superblock over the
/// backend's root inode.
struct FsBackedType { fs: Arc<dyn FileSystem> }
impl FileSystemType for FsBackedType {
    fn name(&self) -> &str { self.fs.name() }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Ok(SuperBlock::for_backend(self.fs.clone(), self.fs.root(),
            next_anon_dev(), String::from(self.fs.name())))
    }
}

/// `statfs(2)` payload a superblock reports (Linux `struct kstatfs`
/// subset). `f_type` mirrors `s_magic`.
#[derive(Clone, Copy, Default)]
pub struct SbStatFs {
    pub f_type:   u64,
    pub f_bsize:  u32,
    pub f_blocks: u64,
    pub f_bfree:  u64,
    pub f_bavail: u64,
    pub f_files:  u64,
    pub f_ffree:  u64,
}

/// `super_operations` (Linux `struct super_operations`) — the per-SB
/// vtable. `alloc_inode`/`destroy_inode` are handled by the backend's
/// `iget` builder + the icache `Weak` reclaim, so the trait carries the
/// remaining lifecycle ops.
pub trait SuperOps: Send + Sync {
    /// `statfs`/`fstatfs` backend. # C: O(1)
    fn statfs(&self) -> KResult<SbStatFs>;
    /// `sync_fs` — flush dirty state. Default no-op (pseudo-fs). # C: FS-dependent
    fn sync_fs(&self, _wait: bool) -> KResult<()> { Ok(()) }
    /// `put_super` — last-umount teardown. Default no-op. # C: O(1)
    fn put_super(&self) {}
}

/// `file_system_type` (Linux `struct file_system_type`) — the registry
/// entry split out of today's monolithic `FileSystem` trait. `mount`
/// is `fill_super`: it builds a fresh `SuperBlock` instance.
pub trait FileSystemType: Send + Sync {
    /// FS-type name: `"ext4"`, `"tmpfs"`. # C: O(1)
    fn name(&self) -> &str;
    /// Build a superblock instance (`fill_super`). # C: FS-dependent
    fn mount(&self, src: &str, opts: &str) -> KResult<Arc<SuperBlock>>;
}

/// `struct super_block`. One per mounted fs instance (`16§2` inv 3).
pub struct SuperBlock {
    /// `s_op` — super_operations vtable.
    pub s_op: Arc<dyn SuperOps>,
    /// `s_type` — file_system_type backref.
    pub s_type: Arc<dyn FileSystemType>,
    /// `s_magic` (linux/magic.h) reported by statfs `f_type`.
    pub s_magic: u64,
    /// `s_dev` — the `st_dev` every inode on this SB reports.
    pub s_dev: u64,
    /// `s_blocksize`.
    pub s_blocksize: u32,
    /// `s_id` — `"/dev/vda1"`, `"tmpfs"`; `/proc/mounts` source column.
    pub s_id: String,
    /// `s_root` — the ROOT DENTRY (strong; see CYCLE NOTE).
    s_root: RwLock<Option<Arc<Dentry>>, SbClass>,
    /// `s_fs_info` — backend-private state (ext4 sb / tmpfs arena).
    s_fs_info: Arc<dyn Any + Send + Sync>,
    /// The legacy `Arc<dyn FileSystem>` backend carrying the write/inode ops
    /// (`create`/`unlink`/`link`/`rename`/`root`/`mounts_line`) that
    /// `SuperOps`/`FileSystemType` do not. The mount table reaches the
    /// backend through `sb.fs()`. `NullFs` for an `s_fs`-less test SB.
    s_fs: Arc<dyn FileSystem>,
    /// Per-instance inode cache (`iget`/`ilookup`/`iput`). `Weak` so an
    /// inode is reclaimed when its last `Arc` drops; a stale `Weak` is
    /// re-inserted on the next `iget`.
    icache: Spinlock<BTreeMap<Ino, Weak<dyn Inode>>, SbClass>,
}

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
            s_op, s_type, s_magic, s_dev, s_blocksize, s_id,
            s_root: RwLock::new(None),
            s_fs_info,
            s_fs: Arc::new(NullFs),
            icache: Spinlock::new(BTreeMap::new()),
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
        let s_op: Arc<dyn SuperOps> = Arc::new(FsBackedSuperOps { fs: fs.clone() });
        let s_type: Arc<dyn FileSystemType> = Arc::new(FsBackedType { fs: fs.clone() });
        let s_magic = fs.magic();
        let sb = Arc::new(Self {
            s_op, s_type, s_magic, s_dev, s_blocksize: 4096, s_id,
            s_root: RwLock::new(None),
            s_fs_info: Arc::new(()),
            s_fs: fs,
            icache: Spinlock::new(BTreeMap::new()),
        });
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

    /// Backend-private state downcast. # C: O(1)
    pub fn fs_info(&self) -> &Arc<dyn Any + Send + Sync> { &self.s_fs_info }

    /// `ilookup` — hit the inode cache. `None` if absent or reclaimed.
    /// # C: O(log N_ino)
    pub fn ilookup(&self, ino: Ino) -> Option<InodeRef> {
        self.icache.lock().get(&ino).and_then(Weak::upgrade)
    }

    /// `iget` — cache hit, else build via the backend closure and cache a
    /// `Weak`. Race-safe: a concurrent inserter wins. # C: O(log N_ino)
    pub fn iget(&self, ino: Ino, build: impl FnOnce() -> InodeRef) -> InodeRef {
        if let Some(i) = self.ilookup(ino) { return i; }
        let inode = build();
        let mut c = self.icache.lock();
        if let Some(existing) = c.get(&ino).and_then(Weak::upgrade) { return existing; }
        c.insert(ino, Arc::downgrade(&inode));
        inode
    }

    /// `iput`/reclaim hook — drop a cache slot whose inode is gone.
    /// # C: O(log N_ino)
    pub fn iforget(&self, ino: Ino) { self.icache.lock().remove(&ino); }

    /// statfs via `s_op`, defaulting `f_type`/`f_bsize` from the SB.
    /// # C: O(1)
    pub fn statfs(&self) -> KResult<SbStatFs> {
        let mut st = self.s_op.statfs()?;
        if st.f_type == 0 { st.f_type = self.s_magic; }
        if st.f_bsize == 0 { st.f_bsize = self.s_blocksize; }
        Ok(st)
    }

    /// Umount teardown: `put_super` then drop the dentry tree. # C: O(tree)
    pub fn put_super(&self) {
        self.s_op.put_super();
        *self.s_root.write() = None;
        self.icache.lock().clear();
    }
}
