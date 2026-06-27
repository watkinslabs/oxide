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

use sync::{RwLock, Spinlock, Superblock as SbClass};

use crate::dentry::Dentry;
use crate::inode::{Inode, InodeRef};
use crate::types::{Ino, KResult};

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
            icache: Spinlock::new(BTreeMap::new()),
        })
    }

    /// The root dentry of this instance (Linux `sb->s_root`). # C: O(1)
    pub fn s_root(&self) -> Option<Arc<Dentry>> { self.s_root.read().clone() }

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
