//! An in-memory filesystem to stand in for a layer.
//!
//! Overlayfs is defined by what it does to the layers under it, so a test that
//! only checks its decision functions proves very little: a copy-up whose
//! steps are reordered still returns the right answer and still loses the file
//! on a crash. These layers are real inodes with real children, attributes,
//! device numbers and rename flags, so a test can build a stack, act on it,
//! and then look at what is actually on each layer afterwards.
//!
//! Every operation the overlay issues against a layer lands here, which also
//! makes this the place a test can watch the ORDER of those operations.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList};
use vfs::file_ops::{DirContext, FileOps};
use vfs::inode::InodeBuilder;
use vfs::inode_ops::{CreateCtx, InodeOps};
use vfs::namei::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};
use vfs::types::{FileType, Ino, S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use vfs::superblock::next_anon_dev;
use vfs::xattr::SimpleXattrs;
use vfs::{SimpleSuperOps, SuperBlock};
use vfs::{Inode, InodeRef, KResult, VfsError};

use crate::uapi::WHITEOUT_RDEV;

/// Per-inode state the VFS inode does not carry: a directory's children and a
/// regular file's bytes.
pub struct Node {
    kids: Spinlock<BTreeMap<String, InodeRef>, TaskList>,
    data: Spinlock<Vec<u8>, TaskList>,
}

impl Node {
    fn new() -> Arc<Node> {
        Arc::new(Node { kids: Spinlock::new(BTreeMap::new()), data: Spinlock::new(Vec::new()) })
    }
}

/// Inode numbering and identity shared by every inode of one layer.
///
/// The superblock is real, because the origin record a copy-up writes is the
/// LAYER's own file handle: without one the record cannot be minted, and every
/// test of shared identity would pass by doing nothing.
struct Alloc { next: AtomicU64, fsid: u64, sb: Spinlock<Option<Weak<SuperBlock>>, TaskList> }

/// Inode numbers start above the reserved low range so a zero in a test is
/// obviously wrong rather than plausibly the root.
const FIRST_INO: u64 = 100;

/// Both vtables of a layer inode. One struct, because a layer's directory and
/// file behaviour are the same store seen two ways.
struct Ops { alloc: Arc<Alloc> }

impl Ops {
    /// Build an inode of this layer. # C: O(1)
    fn make(alloc: &Arc<Alloc>, ino: Ino, mode: u32, rdev: u32, link: Option<&[u8]>) -> InodeRef {
        let ops: Arc<dyn InodeOps> = Arc::new(Ops { alloc: alloc.clone() });
        let fops: Arc<dyn FileOps> = Arc::new(Ops { alloc: alloc.clone() });
        let mut b = InodeBuilder::new(ino, mode, ops, fops)
            .private(Node::new())
            .xattrs(SimpleXattrs::new())
            .rdev(rdev)
            .fsid(alloc.fsid);
        if let Some(sb) = alloc.sb.lock().as_ref() { b = b.sb(sb.clone()); }
        if let Some(l) = link { b = b.link(l.to_vec().into_boxed_slice()); }
        let inode = b.build();
        if let Some(sb) = alloc.sb.lock().as_ref().and_then(|w| w.upgrade()) {
            let made = inode.clone();
            sb.iget(ino, move || made);
        }
        inode
    }
}

/// An empty layer, identified by `fsid`, with its root directory returned.
/// # C: O(1)
pub fn layer(fsid: u64) -> InodeRef {
    let alloc = Arc::new(Alloc { next: AtomicU64::new(FIRST_INO), fsid,
                                 sb: Spinlock::new(None) });
    let root = Ops::make(&alloc, 1, S_IFDIR as u32 | 0o755, 0, None);
    let ty: Arc<dyn vfs::FileSystemType> = vfs::fs::FsType::new(
        "overlay-test-layer", 0, Default::default(),
        alloc::boxed::Box::new(|_, _, _, _, _, _| unreachable!("a test layer is never mounted")));
    let sb = SuperBlock::from_ops(ty, Arc::new(SimpleSuperOps { magic: 0, block_size: 4096,
                                                                options: String::new() }),
                                  Some(root.clone()), 0, next_anon_dev(), 4096,
                                  String::from("overlay-test-layer"), Arc::new(()));
    *alloc.sb.lock() = Some(Arc::downgrade(&sb));
    // The superblock outlives the test only through the root inode, which is
    // what the caller keeps; leaking it here is what makes that true.
    core::mem::forget(sb);
    root
}

/// The private state of a layer inode. # C: O(1)
fn node_of(i: &Inode) -> &Node {
    i.private::<Node>().expect("layer inode")
}

impl Ops {
    /// Build a child of this layer. # C: O(1)
    fn child(&self, mode: u32, rdev: u32, link: Option<&[u8]>) -> InodeRef {
        let ino = self.alloc.next.fetch_add(1, Ordering::Relaxed);
        Ops::make(&self.alloc, ino, mode, rdev, link)
    }

    /// Insert `child` under `name`, refusing to replace. # C: O(log n)
    fn insert(&self, dir: &Inode, name: &str, child: InodeRef) -> KResult<InodeRef> {
        let n = node_of(dir);
        let mut k = n.kids.lock();
        if k.contains_key(name) { return Err(VfsError::Eexist); }
        k.insert(name.to_string(), child.clone());
        Ok(child)
    }
}

impl InodeOps for Ops {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        node_of(inode).kids.lock().get(name).cloned().ok_or(VfsError::Enoent)
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool { node_of(inode).kids.lock().is_empty() }

    fn create(&self, inode: &Inode, name: &str, mode: u32, _c: &CreateCtx) -> KResult<InodeRef> {
        let child = self.child((mode & !S_IFMT as u32) | S_IFREG as u32, 0, None);
        self.insert(inode, name, child)
    }

    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, _c: &CreateCtx) -> KResult<InodeRef> {
        let child = self.child((mode & !S_IFMT as u32) | S_IFDIR as u32, 0, None);
        self.insert(inode, name, child)
    }

    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, _c: &CreateCtx) -> KResult<()> {
        let child = self.child(mode as u32, rdev, None);
        self.insert(inode, name, child).map(|_| ())
    }

    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], _c: &CreateCtx) -> KResult<()> {
        let child = self.child(S_IFLNK as u32 | 0o777, 0, Some(target));
        self.insert(inode, name, child).map(|_| ())
    }

    fn link(&self, inode: &Inode, target: &InodeRef, name: &str, _c: &CreateCtx) -> KResult<()> {
        let r = self.insert(inode, name, target.clone());
        if r.is_ok() { target.inc_nlink(); }
        r.map(|_| ())
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let n = node_of(inode);
        let mut k = n.kids.lock();
        let gone = k.remove(name).ok_or(VfsError::Enoent)?;
        gone.drop_nlink();
        Ok(())
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let n = node_of(inode);
        let mut k = n.kids.lock();
        let victim = k.get(name).ok_or(VfsError::Enoent)?.clone();
        if victim.i_mode() & S_IFMT != S_IFDIR { return Err(VfsError::Enotdir); }
        if !node_of(&victim).kids.lock().is_empty() { return Err(VfsError::Enotempty); }
        k.remove(name);
        Ok(())
    }

    fn rename(&self, inode: &Inode, old: &str, new_dir: &Inode, new: &str, flags: u32,
              c: &CreateCtx) -> KResult<()> {
        rename(self, inode, old, new_dir, new, flags, c)
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let n = node_of(inode);
        n.data.lock().resize(len as usize, 0);
        inode.set_size(len);
        Ok(())
    }

    fn tmpfile(&self, _inode: &Inode, mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let child = self.child((mode & !S_IFMT as u32) | S_IFREG as u32, 0, None);
        child.drop_nlink();
        Ok(child)
    }

    fn fallocate(&self, inode: &Inode, mode: u32, off: u64, len: u64) -> KResult<()> {
        if mode & !vfs::uapi::FALLOC_FL_KEEP_SIZE != 0 { return Err(VfsError::Eopnotsupp); }
        let end = off.checked_add(len).ok_or(VfsError::Einval)?;
        let n = node_of(inode);
        let mut data = n.data.lock();
        if end > data.len() as u64 { data.resize(end as usize, 0); }
        if mode & vfs::uapi::FALLOC_FL_KEEP_SIZE == 0 { inode.set_size(end); }
        Ok(())
    }

    fn fiemap(&self, inode: &Inode, start: u64, len: u64,
              emit: &mut dyn FnMut(vfs::FiemapExtent) -> bool) -> KResult<()> {
        let size = inode.size();
        let end = start.saturating_add(len);
        if start < size && end != 0 {
            let logical = start;
            let length = size.saturating_sub(start).min(end.saturating_sub(start));
            if length != 0 {
                emit(vfs::FiemapExtent { logical, physical: inode.ino() * 4096,
                                         length, flags: vfs::inode::FIEMAP_EXTENT_LAST });
            }
        }
        Ok(())
    }
}

/// Rename within or across two directories of the same layer, honouring the
/// three flags the overlay relies on.
///
/// Overlayfs builds every atomic step out of these: replacing a name with a
/// whiteout is an exchange, and moving a copied-up object into place while
/// leaving a whiteout behind is `RENAME_WHITEOUT`. A layer that quietly
/// ignored a flag would make every one of those steps half-complete.
/// # C: O(log n)
fn rename(ops: &Ops, olddir: &Inode, old: &str, newdir: &Inode, new: &str, flags: u32,
          _c: &CreateCtx) -> KResult<()> {
    let src = node_of(olddir);
    let dst = node_of(newdir);
    let moving = src.kids.lock().get(old).cloned().ok_or(VfsError::Enoent)?;
    let target = dst.kids.lock().get(new).cloned();
    if flags & RENAME_NOREPLACE != 0 && target.is_some() { return Err(VfsError::Eexist); }
    if flags & RENAME_EXCHANGE != 0 {
        let other = target.ok_or(VfsError::Enoent)?;
        dst.kids.lock().insert(new.to_string(), moving);
        src.kids.lock().insert(old.to_string(), other);
        return Ok(());
    }
    dst.kids.lock().insert(new.to_string(), moving);
    src.kids.lock().remove(old);
    if flags & RENAME_WHITEOUT != 0 {
        let w = ops.child(S_IFCHR as u32, WHITEOUT_RDEV, None);
        src.kids.lock().insert(old.to_string(), w);
    }
    Ok(())
}

impl FileOps for Ops {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = node_of(inode).data.lock();
        let off = off as usize;
        if off >= d.len() { return Ok(0); }
        let n = core::cmp::min(buf.len(), d.len() - off);
        buf[..n].copy_from_slice(&d[off..off + n]);
        Ok(n)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        // A write clears the file's capabilities, as the real write path does.
        // Modelling it is what lets a test see that copy-up writes the data
        // BEFORE the attributes rather than after.
        let _ = inode.removexattr(crate::xattr::NAME_CAPS);
        let mut d = node_of(inode).data.lock();
        let off = off as usize;
        if d.len() < off + buf.len() { d.resize(off + buf.len(), 0); }
        d[off..off + buf.len()].copy_from_slice(buf);
        inode.set_size(d.len() as u64);
        Ok(buf.len())
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let kids: Vec<(String, InodeRef)> = node_of(inode).kids.lock()
            .iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (i, (name, child)) in kids.iter().enumerate() {
            let pos = i as u64;
            if pos < ctx.pos { continue; }
            let t = child.file_type();
            if !ctx.emit(name, child.ino(), t, pos + 1) { break; }
        }
        Ok(())
    }
}

/// Create every directory on `path` under `dir`, returning the last. # C: O(len(path))
pub fn mkpath(dir: &InodeRef, path: &str) -> InodeRef {
    let mut cur = dir.clone();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        cur = match cur.lookup(part) {
            Ok(c) => c,
            Err(_) => cur.mkdir(part, S_IFDIR as u32 | 0o755, &CreateCtx::root()).unwrap(),
        };
    }
    cur
}

/// Create a regular file with `body` at `path` under `dir`. # C: O(len(path) + len(body))
pub fn mkfile(dir: &InodeRef, path: &str, body: &[u8]) -> InodeRef {
    let (parent, name) = split(dir, path);
    let f = parent.create_child(name, S_IFREG as u32 | 0o644, &CreateCtx::root()).unwrap();
    if !body.is_empty() { f.write(0, body).unwrap(); }
    f
}

/// Read a whole file back. # C: O(size)
pub fn slurp(f: &InodeRef) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    let mut off = 0u64;
    loop {
        let n = f.read(off, &mut buf).unwrap();
        if n == 0 { break; }
        out.extend_from_slice(&buf[..n]);
        off += n as u64;
    }
    out
}

/// Split `path` into its parent directory (created as needed) and last name.
/// # C: O(len(path))
pub fn split<'a>(dir: &InodeRef, path: &'a str) -> (InodeRef, &'a str) {
    match path.rfind('/') {
        Some(i) => (mkpath(dir, &path[..i]), &path[i + 1..]),
        None => (dir.clone(), path),
    }
}

/// Resolve `path` from `dir`. # C: O(len(path))
pub fn lookup(dir: &InodeRef, path: &str) -> Option<InodeRef> {
    let mut cur = dir.clone();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        cur = cur.lookup(part).ok()?;
    }
    Some(cur)
}

/// Names in `dir`, in the order the layer emits them. # C: O(entries)
pub fn names(dir: &InodeRef) -> Vec<String> {
    struct Sink(Vec<String>);
    impl vfs::file_ops::DirEmit for Sink {
        fn emit(&mut self, name: &str, _ino: u64, _t: FileType, _next: u64) -> bool {
            self.0.push(name.to_string());
            true
        }
    }
    let mut sink = Sink(Vec::new());
    let mut ctx = DirContext::new(0, &mut sink);
    dir.readdir(&mut ctx).unwrap();
    sink.0
}

/// Make `f` a whiteout in `dir` under `name`, the way a layer written by
/// another kernel would carry one. # C: O(1)
pub fn mkwhiteout(dir: &InodeRef, name: &str) {
    dir.mknod_child(name, S_IFCHR, WHITEOUT_RDEV, &CreateCtx::root()).unwrap();
}

/// Build a mount over `upper` and `lowers`, and the root object's own layer
/// list. Data-only layers are named by index in `data`. # C: O(layers)
pub fn stack(config: crate::config::Config, upper: Option<InodeRef>, lowers: &[InodeRef],
             data: &[usize]) -> (Arc<crate::layers::LayerStack>, crate::layers::OvlEntry) {
    use crate::layers::{Layer, LayerStack, OvlEntry, OvlPath};
    let upper_layer = upper.as_ref().map(|u| Layer::new(u.clone(), 0, 0, false));
    let mut lower = Vec::new();
    let mut root = OvlEntry { upper: upper.clone(), upper_alias: upper.is_some(),
                              ..OvlEntry::default() };
    for (i, l) in lowers.iter().enumerate() {
        let layer = Layer::new(l.clone(), i + 1, (i + 1) as u32, data.contains(&i));
        root.lower.push(OvlPath { layer: layer.clone(), inode: l.clone() });
        lower.push(layer);
    }
    let workdir = upper.as_ref().map(|u| mkpath(u, "..work"));
    let stack = Arc::new(LayerStack {
        config, creator_cred: vfs::Cred::root(), upper: upper_layer, lower, workdir, indexdir: None,
        xino: crate::xino::Mode::Off, namelen: crate::limits::NAME_MAX,
        noxattr: core::sync::atomic::AtomicBool::new(false), root: root.clone(),
        inode_cache: sync::Spinlock::new(BTreeMap::new()),
    });
    (stack, root)
}
