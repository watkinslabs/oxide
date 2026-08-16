// The mounted 9P filesystem: session, policy, inode identity, superblock face.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};

use ninep::client::{Client, FidRef};
use ninep::codec::Qid;
use ninep::opts::MountOpts;
use ninep::uapi::stats;
use sync::{Spinlock, Tty as NpClass};
use vfs::fs::FileSystem;
use vfs::{Inode, InodeBuilder, InodeRef, KResult, SbStatFs, SuperOps, VfsError};

use super::attr::{self, AttrPolicy, InodeFacts};
use super::file::NinepFileOps;
use super::inode::NinepInodeOps;

/// Backend state on every 9P inode.
pub struct NinepInodeData {
    /// The mount this inode belongs to.
    pub mount: Arc<NinepMount>,
    /// The server handle this inode is addressed through. Held for the inode's
    /// life: rebuilding it on demand would need the full path, and a rename of
    /// an ancestor would make that path resolve somewhere else.
    pub fid: FidRef,
}

/// Recover the backend state off a 9P inode. # C: O(1)
pub fn data(inode: &Inode) -> KResult<&NinepInodeData> {
    inode.private::<NinepInodeData>().ok_or(VfsError::Einval)
}

/// One mounted 9P session.
pub struct NinepMount {
    /// The protocol session.
    pub client: Arc<Client>,
    /// Parsed mount options; the policy every op consults.
    pub opts: MountOpts,
    /// The attach handle for the tree root.
    pub root_fid: FidRef,
    /// `qid.path -> inode`, so a name reached by two paths resolves to ONE
    /// object. Without it a hard link, or a directory reached through `..`,
    /// becomes two inodes with independent sizes and page caches.
    inodes: Spinlock<BTreeMap<u64, Weak<Inode>>, NpClass>,
}

impl NinepMount {
    /// # C: O(1)
    pub fn policy(&self) -> AttrPolicy {
        AttrPolicy { nodev: self.opts.nodev, dfltuid: self.opts.dfltuid, dfltgid: self.opts.dfltgid }
    }

    /// Live inode cached for `path`, if any. # C: O(log N)
    pub fn cached(&self, path: u64) -> Option<InodeRef> {
        self.inodes.lock().get(&path).and_then(Weak::upgrade)
    }

    /// File `inode` under `path` for later lookups to reuse. # C: O(log N)
    pub fn cache(&self, path: u64, inode: &InodeRef) {
        self.inodes.lock().insert(path, Arc::downgrade(inode));
    }

    /// Drop a cached identity. # C: O(log N)
    pub fn forget(&self, path: u64) { self.inodes.lock().remove(&path); }
}

/// Build (or refresh) the inode for the object `fid` names.
///
/// A repeat of a known `qid.path` REFRESHES the live inode rather than making a
/// second one, so the VFS keeps one object per server object. The stat is
/// fetched here rather than by the caller because an inode built without one
/// would carry a zero size and mode that later reads take as truth.
/// # C: RPC + O(log N)
pub fn build_inode(mount: &Arc<NinepMount>, fid: &FidRef) -> KResult<InodeRef> {
    let qid = fid.qid();
    let st = mount.client.getattr(fid, attr::LOOKUP_MASK).map_err(VfsError::from)?;
    let facts = attr::facts_from_stat(&qid, &st, mount.policy());
    if let Some(existing) = mount.cached(facts.ino) {
        refresh_inode(&existing, &facts);
        return Ok(existing);
    }
    let inode = InodeBuilder::new(facts.ino, facts.mode,
            Arc::new(NinepInodeOps), Arc::new(NinepFileOps))
        .size(facts.size)
        .blocks(facts.blocks)
        .nlink(facts.nlink.max(1))
        .owner(facts.uid, facts.gid)
        .rdev(facts.rdev)
        .times(facts.atime, facts.mtime, facts.ctime)
        .private(Arc::new(NinepInodeData { mount: mount.clone(), fid: fid.clone() }))
        .build();
    mount.cache(facts.ino, &inode);
    Ok(inode)
}

/// Apply a fresh attribute answer to a live inode. # C: O(1)
pub fn refresh_inode(inode: &InodeRef, facts: &InodeFacts) {
    inode.set_size(facts.size);
    if facts.nlink != 0 { inode.set_nlink(facts.nlink); }
    let _ = inode.set_times(Some(facts.atime), Some(facts.mtime), facts.ctime);
}

/// Re-read an inode's attributes from the server. # C: RPC
pub fn refresh(inode: &Inode) -> KResult<()> {
    let d = data(inode)?;
    let st = d.mount.client.getattr(&d.fid, stats::ALL).map_err(VfsError::from)?;
    let facts = attr::facts_from_stat(&d.fid.qid(), &st, d.mount.policy());
    inode.set_size(facts.size);
    if facts.nlink != 0 { inode.set_nlink(facts.nlink); }
    let _ = inode.set_times(Some(facts.atime), Some(facts.mtime), facts.ctime);
    Ok(())
}

/// The mounted instance's VFS face.
pub struct NinepFs {
    mount: Arc<NinepMount>,
    root: InodeRef,
    options: String,
}

impl NinepFs {
    /// The session this mount speaks over. # C: O(1)
    pub fn mount(&self) -> &Arc<NinepMount> { &self.mount }
    /// The tree root inode. # C: O(1)
    pub fn root_inode(&self) -> InodeRef { self.root.clone() }
}

/// `super_operations` for a 9P mount.
pub struct NinepSuperOps {
    mount: Arc<NinepMount>,
    options: String,
}

impl SuperOps for NinepSuperOps {
    /// Ask the server for its counters. A server with no `Tstatfs` is not a
    /// broken mount, so the fixed identity is reported instead of an error.
    /// # C: RPC
    fn statfs(&self) -> KResult<SbStatFs> {
        let bsize = self.mount.opts.msize.saturating_sub(ninep::uapi::limits::IOHDRSZ as u32);
        let Ok(s) = self.mount.client.statfs(&self.mount.root_fid) else {
            return Ok(SbStatFs { f_type: ninep::V9FS_MAGIC, f_bsize: bsize, ..Default::default() });
        };
        Ok(SbStatFs {
            f_type: ninep::V9FS_MAGIC,
            f_bsize: if s.bsize != 0 { s.bsize } else { bsize },
            f_blocks: s.blocks, f_bfree: s.bfree, f_bavail: s.bavail,
            f_files: s.files, f_ffree: s.ffree,
            f_namelen: u64::from(s.namelen),
            ..Default::default()
        })
    }
    /// # C: O(1)
    fn show_options(&self) -> String { self.options.clone() }
    /// A forced unmount on a wedged server: tearing the session down completes
    /// every outstanding request so the references pinning the mount are
    /// released and the unmount can proceed. # C: O(N_inflight)
    fn umount_begin(&self, _sb: &vfs::SuperBlock) { self.mount.client.shutdown(); }
}

impl FileSystem for NinepFs {
    /// # C: O(1)
    fn name(&self) -> &str { "9p" }
    /// # C: O(1)
    fn magic(&self) -> u64 { ninep::V9FS_MAGIC }
    /// A 9P mount's block size is the negotiated frame minus its envelope: it
    /// is the largest transfer that fits one message, which is the only unit
    /// that means anything here. # C: O(1)
    fn block_size(&self) -> u32 {
        self.mount.opts.msize.saturating_sub(ninep::uapi::limits::IOHDRSZ as u32)
    }
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
    /// # C: O(1)
    fn show_options(&self) -> String { self.options.clone() }
    /// # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> {
        Some(Arc::new(NinepSuperOps { mount: self.mount.clone(), options: self.options.clone() }))
    }
}

/// Establish a session over `transport` and build the mounted filesystem.
///
/// Order matters: the version handshake settles the dialect and frame size
/// BEFORE the attach, because an attach encoded for the wrong dialect carries
/// a numeric identity field the server is not expecting. # C: two RPCs
pub fn mount_session(transport: ninep::TransportRef, opts: MountOpts, uid: u32)
    -> KResult<Arc<NinepFs>>
{
    let client = Client::new(transport, opts.version, opts.msize).map_err(VfsError::from)?;
    let negotiated = client.version().map_err(VfsError::from)?;
    let mut opts = opts;
    opts.version = negotiated.dialect;
    opts.msize = negotiated.msize;
    let root_fid = client.attach(None, &opts.uname, &opts.aname, uid).map_err(VfsError::from)?;
    let options = opts.show();
    let mount = Arc::new(NinepMount {
        client, opts, root_fid: root_fid.clone(),
        inodes: Spinlock::new(BTreeMap::new()),
    });
    let root = build_inode(&mount, &root_fid)?;
    Ok(Arc::new(NinepFs { mount, root, options }))
}

/// Look up the object named `name` under the directory `parent`, returning the
/// handle for it. `Enoent` when the name does not resolve. # C: RPC
pub fn walk_child(mount: &Arc<NinepMount>, parent: &FidRef, name: &str) -> KResult<FidRef> {
    mount.client.walk(parent, &[name], true).map_err(VfsError::from)
}

/// The identity of the object a handle names, for cache bookkeeping. # C: O(1)
pub fn fid_qid(fid: &FidRef) -> Qid { fid.qid() }
