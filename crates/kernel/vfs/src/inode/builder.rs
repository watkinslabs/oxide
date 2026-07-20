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
use crate::types::{Ino, S_IFDIR};

use super::model::{Inode, OwnerPersist, SealCarrier};

/// Builder for [`Inode`] — the one constructor every `make_*_inode` / `iget`
/// build closure funnels through.
pub struct InodeBuilder {
    ino:          Ino,
    mode:         u32,
    i_op:         Arc<dyn InodeOps>,
    i_fop:        Arc<dyn FileOps>,
    sb:           Weak<SuperBlock>,
    size:         u64,
    blocks:       u64,
    nlink:        Option<u32>,
    uid:          u32,
    gid:          u32,
    projid:       u32,
    flags:        u32,
    rdev:         u32,
    generation:   u32,
    fsid:         u64,
    atime:        u64,
    mtime:        u64,
    ctime:        u64,
    btime:        u64,
    version:      u64,
    mapping:      Option<Arc<dyn AddressSpaceOps>>,
    private:      Arc<dyn Any + Send + Sync>,
    poll_subs:    Option<Arc<PollSubscribers>>,
    seal_carrier: Option<Arc<dyn SealCarrier>>,
    owner_persist:Option<Arc<dyn OwnerPersist>>,
    link:         Option<Box<[u8]>>,
    xattrs:       Option<crate::xattr::SimpleXattrs>,
}

impl InodeBuilder {
    /// Start a build with the inode number, full `umode_t`, and the two vtables. # C: O(1)
    pub fn new(ino: Ino, mode: u32, i_op: Arc<dyn InodeOps>, i_fop: Arc<dyn FileOps>) -> Self {
        InodeBuilder {
            ino, mode, i_op, i_fop, sb: Weak::new(), size: 0, blocks: 0, nlink: None, uid: 0, gid: 0,
            projid: 0, flags: 0, rdev: 0, generation: 0, fsid: 0, atime: 0, mtime: 0, ctime: 0, btime: 0,
            version: 0, mapping: None, private: Arc::new(()), poll_subs: None, seal_carrier: None,
            owner_persist: None, link: None, xattrs: None,
        }
    }
    pub fn sb(mut self, sb: Weak<SuperBlock>) -> Self { self.sb = sb; self }
    pub fn size(mut self, n: u64) -> Self { self.size = n; self }
    pub fn blocks(mut self, n: u64) -> Self { self.blocks = n; self }
    pub fn nlink(mut self, n: u32) -> Self { self.nlink = Some(n); self }
    pub fn owner(mut self, uid: u32, gid: u32) -> Self { self.uid = uid; self.gid = gid; self }
    pub fn projid(mut self, projid: u32) -> Self { self.projid = projid; self }
    pub fn i_flags(mut self, f: u32) -> Self { self.flags = f; self }
    pub fn rdev(mut self, d: u32) -> Self { self.rdev = d; self }
    pub fn generation(mut self, g: u32) -> Self { self.generation = g; self }
    pub fn fsid(mut self, f: u64) -> Self { self.fsid = f; self }
    pub fn times(mut self, a: u64, m: u64, c: u64) -> Self { self.atime = a; self.mtime = m; self.ctime = c; self }
    pub fn btime(mut self, b: u64) -> Self { self.btime = b; self }
    pub fn version(mut self, v: u64) -> Self { self.version = v; self }
    pub fn mapping(mut self, m: Arc<dyn AddressSpaceOps>) -> Self { self.mapping = Some(m); self }
    pub fn private(mut self, p: Arc<dyn Any + Send + Sync>) -> Self { self.private = p; self }
    pub fn poll_subs(mut self, p: PollSubscribers) -> Self { self.poll_subs = Some(Arc::new(p)); self }
    pub fn poll_subs_arc(mut self, p: Arc<PollSubscribers>) -> Self { self.poll_subs = Some(p); self }
    pub fn seal_carrier(mut self, c: Arc<dyn SealCarrier>) -> Self { self.seal_carrier = Some(c); self }
    /// Install a backend chown write-through ([`OwnerPersist`]) — a synthesized
    /// inode (cgroupfs) uses it so `chown(2)` persists to the backing store. # C: O(1)
    pub fn owner_persist(mut self, p: Arc<dyn OwnerPersist>) -> Self { self.owner_persist = Some(p); self }
    pub fn link(mut self, body: Box<[u8]>) -> Self { self.link = Some(body); self }
    pub fn xattrs(mut self, x: crate::xattr::SimpleXattrs) -> Self { self.xattrs = Some(x); self }

    /// Finish the build. # C: O(1)
    pub fn build(self) -> Arc<Inode> {
        let nlink = self.nlink.unwrap_or_else(|| default_nlink(self.mode));
        Arc::new(Inode {
            i_ino: self.ino,
            i_mode: AtomicU32::new(self.mode),
            i_size: AtomicU64::new(self.size),
            i_blocks: AtomicU64::new(self.blocks),
            i_nlink: AtomicU32::new(nlink),
            i_uid: AtomicU32::new(self.uid),
            i_gid: AtomicU32::new(self.gid),
            i_projid: AtomicU32::new(self.projid),
            i_flags: AtomicU32::new(self.flags),
            i_rdev: self.rdev,
            i_generation: self.generation,
            i_atime: AtomicU64::new(self.atime),
            i_mtime: AtomicU64::new(self.mtime),
            i_ctime: AtomicU64::new(self.ctime),
            i_btime: self.btime,
            i_state: AtomicU32::new(0),
            i_count: AtomicU32::new(1),
            i_version: AtomicU64::new(self.version),
            i_fsid: AtomicU64::new(self.fsid),
            i_sb: self.sb,
            i_mapping: self.mapping,
            i_file_rmap: vmm::FileRmap::new(),
            i_op: self.i_op,
            i_fop: self.i_fop,
            i_private: self.private,
            poll_subs: self.poll_subs,
            seal_carrier: self.seal_carrier,
            owner_persist: self.owner_persist,
            i_link: self.link,
            i_xattrs: self.xattrs,
            i_dquot: InodeDquots::new(),
            i_rwsem: super::rwsem::InodeRwsem::new(),
            i_flctx: super::file_lock::FileLockContext::new(),
        })
    }
}

fn default_nlink(mode: u32) -> u32 {
    if (mode as u16 & crate::types::S_IFMT) == S_IFDIR { 2 } else { 1 }
}
