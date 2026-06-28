//! Generic pseudo-filesystem tree (Linux `fs/kernfs` shape). `PseudoDir`
//! is a real per-component `vfs::Inode`: its `children` BTreeMap IS the
//! directory and resolution is per-component `i_op->lookup`, never a
//! whole-path key. Lifted from devfs's `DevDir` (D1) and given a `Weak<
//! SuperBlock>` (`i_sb`, the tmpfs `TmpfsDir` precedent) plus an optional
//! per-dir ext4-overlay so each pseudo-fs (devfs/sysfs/procfs/tracefs/
//! devpts) can OWN its own tree under its SuperBlock instead of a shared
//! global path registry (D1b).
//!
//! `readdir` enumerates its (sorted) BTreeMap children THEN, when
//! `overlay` is set, the ext4 overlay for its own path (skipping
//! synthetic-shadowed names) — mirroring devtmpfs's `/dev` + `/etc`
//! merge. Trees that have no on-disk backing (sysfs/procfs subtrees)
//! leave `overlay` off and emit children only.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::superblock::SuperBlock;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

// ---------------------------------------------------------------------------
// ext4 directory-overlay hook (installed once at boot by the kernel).
// ---------------------------------------------------------------------------

/// Directory-overlay hook: emits real on-disk children (the rootfs) under a
/// path prefix, so synthetic dirs (`/dev`, `/etc`) overlay ext4 without
/// kernfs depending on a filesystem driver (would cycle kernfs->ext4->
/// block->cgroup->...). The kernel installs an ext4 adapter at boot (docs/56).
static DIR_OVERLAY: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
type OverlayFn = fn(&[u8], &mut dyn FnMut(&[u8], FileType));

/// Install the rootfs directory-overlay adapter. Boot, once.
/// # C: O(1)
pub fn set_dir_overlay(f: OverlayFn) { DIR_OVERLAY.store(f as *mut (), Ordering::Release); }

/// Emit on-disk ext4 children under `prefix` via the installed adapter.
/// Called by `PseudoDir::readdir` (overlay dirs only) to merge real entries
/// with synthetic ones. # C: O(N ext4 children)
fn dir_overlay(prefix: &[u8], emit: &mut dyn FnMut(&[u8], FileType)) {
    let p = DIR_OVERLAY.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: p was stored from an OverlayFn via set_dir_overlay; the fn
    // pointer type round-trips through *mut () unchanged.
    let f: OverlayFn = unsafe { core::mem::transmute(p) };
    f(prefix, emit);
}

// ---------------------------------------------------------------------------
// Inode-number derivation (FNV-1a, tagged into the synthetic-dir range).
// ---------------------------------------------------------------------------

/// Deterministic inode number from a path (FNV-1a, tagged into the
/// synthetic-dir range so it never collides with leaf inodes). # C: O(len)
pub fn dir_ino(path: &str) -> Ino {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.as_bytes() { h ^= *b as u64; h = h.wrapping_mul(0x0000_0100_0000_01b3); }
    0x5000_0000_0000_0000 | (h & 0x0fff_ffff_ffff_ffff)
}

/// Split an absolute path into non-empty components. # C: O(len)
fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|c| !c.is_empty()).collect()
}

// ---------------------------------------------------------------------------
// PseudoSymlink
// ---------------------------------------------------------------------------

/// A symlink leaf in a pseudo-fs tree (lifted from devfs `DevSymlink`,
/// `i_sb`-stamped). `readlink` returns the stored target.
pub struct PseudoSymlink {
    ino:    Ino,
    fsid:   u64,
    sb:     Spinlock<Weak<SuperBlock>, TaskListClass>,
    target: Vec<u8>,
}

impl PseudoSymlink {
    /// # C: O(target)
    pub fn new(ino: Ino, fsid: u64, target: &[u8]) -> Arc<Self> {
        Arc::new(Self { ino, fsid, sb: Spinlock::new(Weak::new()), target: target.to_vec() })
    }
}

impl Inode for PseudoSymlink {
    fn ino(&self) -> Ino { self.ino }
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.lock().upgrade() }
    fn fsid(&self) -> u64 { self.sb.lock().upgrade().map(|s| s.s_dev).unwrap_or(self.fsid) }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> { Ok(self.target.clone()) }
}

// ---------------------------------------------------------------------------
// PseudoDir
// ---------------------------------------------------------------------------

/// A child of a `PseudoDir`: a subdirectory or a registered leaf inode
/// (device node, symlink, static/dynamic file).
enum PseudoEntry { Dir(Arc<PseudoDir>), Leaf(InodeRef) }

impl PseudoEntry {
    fn file_type(&self) -> FileType {
        match self { PseudoEntry::Dir(_) => FileType::Directory, PseudoEntry::Leaf(i) => i.file_type() }
    }
    fn as_inode(&self) -> InodeRef {
        match self { PseudoEntry::Dir(d) => Arc::clone(d) as InodeRef, PseudoEntry::Leaf(i) => Arc::clone(i) }
    }
}

/// A mutable directory in a pseudo-fs tree. Drivers register nodes at
/// runtime, so `children` is behind a spinlock. `path` is the dir's
/// absolute path (root = ""), used to drive the ext4 overlay. `fsid` is the
/// fallback filesystem id when no `SuperBlock` is stamped; once `set_sb`
/// runs at `fill_super`, `fsid`/`i_sb` derive from the SB's `s_dev`.
/// `overlay` gates the ext4 readdir merge (devtmpfs `/dev`, rootfs `/etc`).
pub struct PseudoDir {
    ino:      Ino,
    path:     String,
    fsid:     u64,
    overlay:  bool,
    sb:       Spinlock<Weak<SuperBlock>, TaskListClass>,
    children: Spinlock<BTreeMap<String, PseudoEntry>, TaskListClass>,
}

impl PseudoDir {
    /// A fresh root dir (`path == ""`). `root_ino` is the stable root inode
    /// number; `fsid` the fallback filesystem id; `overlay` whether readdir
    /// merges the ext4 overlay for this subtree. # C: O(1)
    pub fn new_root(root_ino: Ino, fsid: u64, overlay: bool) -> Arc<PseudoDir> {
        Arc::new(PseudoDir {
            ino: root_ino, path: String::new(), fsid, overlay,
            sb: Spinlock::new(Weak::new()),
            children: Spinlock::new(BTreeMap::new()),
        })
    }

    /// Internal: a non-root dir at `path` inheriting `fsid`/`overlay`/`sb`.
    /// # C: O(1)
    fn child_at(path: String, fsid: u64, overlay: bool, sb: Weak<SuperBlock>) -> Arc<PseudoDir> {
        Arc::new(PseudoDir {
            ino: dir_ino(&path), path, fsid, overlay,
            sb: Spinlock::new(sb),
            children: Spinlock::new(BTreeMap::new()),
        })
    }

    /// Stamp the owning SB (`fill_super`); after this `fsid`/`i_sb` derive
    /// from `s_dev`. Recurses into existing children so a whole pre-built
    /// tree adopts the SB. # C: O(tree)
    pub fn set_sb(&self, sb: Weak<SuperBlock>) {
        *self.sb.lock() = sb.clone();
        let g = self.children.lock();
        for v in g.values() {
            if let PseudoEntry::Dir(d) = v { d.set_sb(sb.clone()); }
        }
    }

    /// This dir's owning-SB weak (handed to children it creates). # C: O(1)
    fn sb_weak(&self) -> Weak<SuperBlock> { self.sb.lock().clone() }

    /// Get-or-create the subdirectory `name`, building its absolute path.
    /// # C: O(log children)
    fn child_dir(self: &Arc<PseudoDir>, name: &str) -> Arc<PseudoDir> {
        let mut g = self.children.lock();
        if let Some(PseudoEntry::Dir(d)) = g.get(name) { return Arc::clone(d); }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let d = PseudoDir::child_at(cp, self.fsid, self.overlay, self.sb_weak());
        g.insert(String::from(name), PseudoEntry::Dir(Arc::clone(&d)));
        d
    }

    /// Register `full_path` → `inode`. Walks/creates the intermediate dirs
    /// and inserts a `Leaf` at the last component. A `Dir` already present at
    /// the leaf name is kept (registering a node where an intermediate dir
    /// was auto-created is not a conflict). Re-registration overwrites a leaf.
    /// (= old `tree::register`.) # C: O(depth)
    pub fn insert_path(self: &Arc<PseudoDir>, full_path: &str, inode: InodeRef) {
        let comps = components(full_path);
        if comps.is_empty() { return; }
        let mut dir = Arc::clone(self);
        for c in &comps[..comps.len() - 1] { dir = dir.child_dir(c); }
        let leaf = comps[comps.len() - 1];
        let mut g = dir.children.lock();
        match g.get(leaf) {
            Some(PseudoEntry::Dir(_)) => {}
            _ => { g.insert(String::from(leaf), PseudoEntry::Leaf(inode)); }
        }
    }

    /// Create the directory chain `path` as empty dirs — for mount points
    /// with no registered leaf children (e.g. `/sys/fs/cgroup`). The walked
    /// mountpoint dentry is what the mount engine takes. (= old
    /// `tree::register_dir`.) # C: O(components)
    pub fn ensure_dir_path(self: &Arc<PseudoDir>, path: &str) {
        let comps = components(path);
        let mut dir = Arc::clone(self);
        for c in &comps { dir = dir.child_dir(c); }
        let _ = dir;
    }

    /// Resolve `full_path` from this root. A leaf mid-path → `None`; a dir as
    /// the final component → the dir; the empty path → this root. (= old
    /// `tree::lookup`.) # C: O(depth)
    pub fn lookup_path(self: &Arc<PseudoDir>, full_path: &str) -> Option<InodeRef> {
        let comps = components(full_path);
        if comps.is_empty() { return Some(Arc::clone(self) as InodeRef); }
        let mut dir = Arc::clone(self);
        for (i, c) in comps.iter().enumerate() {
            let g = dir.children.lock();
            match g.get(*c) {
                Some(PseudoEntry::Leaf(inode)) => {
                    if i == comps.len() - 1 { return Some(Arc::clone(inode)); }
                    return None; // leaf mid-path
                }
                Some(PseudoEntry::Dir(d)) => {
                    let d = Arc::clone(d);
                    drop(g);
                    if i == comps.len() - 1 { return Some(d as InodeRef); }
                    dir = d;
                }
                None => return None,
            }
        }
        None
    }

    /// Remove the entry at `path` (and its subtree — dropping the
    /// `Arc<PseudoDir>` drops its children). Returns 1 if removed, else 0.
    /// (= old `tree::unregister_subtree`.) # C: O(depth)
    pub fn remove_subtree(self: &Arc<PseudoDir>, path: &str) -> usize {
        let comps = components(path);
        if comps.is_empty() { return 0; }
        let mut dir = Arc::clone(self);
        for c in &comps[..comps.len() - 1] {
            let next = { let g = dir.children.lock();
                match g.get(*c) { Some(PseudoEntry::Dir(d)) => Arc::clone(d), _ => return 0 } };
            dir = next;
        }
        let leaf = comps[comps.len() - 1];
        if dir.children.lock().remove(leaf).is_some() { 1 } else { 0 }
    }

    /// Recursively deep-clone this dir (subdirs cloned, leaf Arcs shared).
    /// Used by clone(CLONE_NEWNS)/unshare. (= old `tree::snapshot_ns` core.)
    /// # C: O(tree)
    pub fn deep_clone(&self) -> Arc<PseudoDir> {
        let g = self.children.lock();
        let mut nc: BTreeMap<String, PseudoEntry> = BTreeMap::new();
        for (k, v) in g.iter() {
            let nv = match v {
                PseudoEntry::Dir(d)  => PseudoEntry::Dir(d.deep_clone()),
                PseudoEntry::Leaf(i) => PseudoEntry::Leaf(Arc::clone(i)),
            };
            nc.insert(k.clone(), nv);
        }
        Arc::new(PseudoDir {
            ino: self.ino, path: self.path.clone(), fsid: self.fsid, overlay: self.overlay,
            sb: Spinlock::new(self.sb.lock().clone()),
            children: Spinlock::new(nc),
        })
    }
}

impl Inode for PseudoDir {
    /// # C: O(1)
    fn ino(&self) -> Ino { self.ino }
    /// # C: O(1)
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    /// # C: O(1)
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.lock().upgrade() }
    /// `fsid` from the owning SB's `s_dev`, else the fallback. # C: O(1)
    fn fsid(&self) -> u64 { self.sb.lock().upgrade().map(|s| s.s_dev).unwrap_or(self.fsid) }
    /// # C: O(1)
    fn file_type(&self) -> FileType { FileType::Directory }
    /// # C: O(1)
    fn size(&self) -> u64 { 0 }
    /// # C: O(log children)
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let g = self.children.lock();
        g.get(name).map(|e| e.as_inode()).ok_or(VfsError::Enoent)
    }
    /// Pseudo-fs dirs are mutable: systemd/tmpfiles create mountpoint dirs
    /// and runtime symlinks (e.g. `/dev/log`) during early boot. # C: O(log children)
    fn mkdir(&self, name: &str, _mode: u32) -> KResult<InodeRef> {
        let mut g = self.children.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let d = PseudoDir::child_at(cp, self.fsid, self.overlay, self.sb_weak());
        g.insert(String::from(name), PseudoEntry::Dir(Arc::clone(&d)));
        Ok(d as InodeRef)
    }
    /// # C: O(log children + target)
    fn symlink_child(&self, name: &str, target: &[u8]) -> KResult<()> {
        let mut g = self.children.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let link = PseudoSymlink::new(dir_ino(&cp), self.fsid, target) as InodeRef;
        g.insert(String::from(name), PseudoEntry::Leaf(link));
        Ok(())
    }
    /// # C: O(children + overlay)
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        // Synthetic children first (BTreeMap → sorted, stable order).
        let kids: Vec<(String, FileType)> = {
            let g = self.children.lock();
            g.iter().map(|(k, v)| (k.clone(), v.file_type())).collect()
        };
        let r_len = kids.len() as u64;
        let mut idx = off as usize;
        while idx < kids.len() {
            let (name, ft) = &kids[idx];
            let next = idx as u64 + 1;
            if !f(next, name, *ft) { return Ok(next); }
            idx += 1;
        }
        if !self.overlay { return Ok(r_len); }
        // ext4 overlay for this dir's path, skipping synthetic-shadowed names.
        let mut ext4_seen: u64 = 0;
        let mut stopped = false;
        let mut stop_off: u64 = (idx as u64).max(r_len);
        let prefix: &str = if self.path.is_empty() { "/" } else { &self.path };
        dir_overlay(prefix.as_bytes(), &mut |name_bytes, ftype| {
            if stopped { return; }
            ext4_seen += 1;
            if r_len + ext4_seen <= off { return; }
            let name = match core::str::from_utf8(name_bytes) { Ok(s) => s, Err(_) => return };
            if kids.iter().any(|(k, _)| k.as_str() == name) { return; }
            let next = r_len + ext4_seen;
            if !f(next, name, ftype) { stopped = true; stop_off = next; }
        });
        if stopped { return Ok(stop_off); }
        Ok(r_len + ext4_seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> Arc<PseudoDir> { PseudoDir::new_root(0x5000_0001, 0xDEAD, false) }

    #[test]
    fn insert_then_lookup_per_component() {
        let r = root();
        let leaf = PseudoSymlink::new(1, 0xDEAD, b"/target") as InodeRef;
        r.insert_path("/sys/kernel/osrelease", leaf);
        // Per-component walk resolves the leaf.
        let got = r.lookup_path("/sys/kernel/osrelease").expect("leaf");
        assert_eq!(got.file_type(), FileType::Symlink);
        // Intermediate dirs were auto-created and are walkable.
        let kdir = r.lookup_path("/sys/kernel").expect("intermediate dir");
        assert_eq!(kdir.file_type(), FileType::Directory);
        // Direct per-component lookup matches whole-path resolution.
        let sys = r.lookup("sys").expect("sys child");
        assert_eq!(sys.lookup("kernel").expect("kernel child").file_type(), FileType::Directory);
    }

    #[test]
    fn leaf_mid_path_is_none() {
        let r = root();
        r.insert_path("/a/b", PseudoSymlink::new(2, 0, b"x") as InodeRef);
        // /a/b is a leaf; resolving through it must fail.
        assert!(r.lookup_path("/a/b/c").is_none());
    }

    #[test]
    fn readdir_sorted_and_no_overlay_when_off() {
        let r = root();
        r.insert_path("/z", PseudoSymlink::new(3, 0, b"z") as InodeRef);
        r.insert_path("/a", PseudoSymlink::new(4, 0, b"a") as InodeRef);
        r.insert_path("/m", PseudoSymlink::new(5, 0, b"m") as InodeRef);
        let mut names = std::vec::Vec::new();
        r.readdir(0, &mut |_n, name, _ft| { names.push(std::string::String::from(name)); true }).unwrap();
        // BTreeMap → sorted; overlay off → exactly the 3 synthetic children.
        assert_eq!(names, std::vec!["a", "m", "z"]);
    }

    #[test]
    fn ensure_dir_path_creates_empty_mountpoint() {
        let r = root();
        r.ensure_dir_path("/sys/fs/cgroup");
        let d = r.lookup_path("/sys/fs/cgroup").expect("mountpoint dir");
        assert_eq!(d.file_type(), FileType::Directory);
    }

    #[test]
    fn deep_clone_is_independent() {
        let r = root();
        r.insert_path("/dev/null", PseudoSymlink::new(6, 0, b"n") as InodeRef);
        let c = r.deep_clone();
        // Mutating the clone does not affect the source.
        c.insert_path("/dev/extra", PseudoSymlink::new(7, 0, b"e") as InodeRef);
        assert!(c.lookup_path("/dev/extra").is_some());
        assert!(r.lookup_path("/dev/extra").is_none());
        // Shared leaves still present in both.
        assert!(r.lookup_path("/dev/null").is_some());
        assert!(c.lookup_path("/dev/null").is_some());
    }

    #[test]
    fn remove_subtree_drops_branch() {
        let r = root();
        r.insert_path("/dev/pts/0", PseudoSymlink::new(8, 0, b"0") as InodeRef);
        assert_eq!(r.remove_subtree("/dev/pts"), 1);
        assert!(r.lookup_path("/dev/pts").is_none());
        assert_eq!(r.remove_subtree("/dev/pts"), 0);
    }
}
