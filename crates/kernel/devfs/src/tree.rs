//! Real per-namespace devfs directory tree (Linux devtmpfs/sysfs shape).
//!
//! Replaces the flat `(ns, full_path, inode)` registry. Each namespace
//! owns an `Arc<DevDir>` root (path = ""); `register` walks/creates
//! intermediate `DevDir`s and inserts a `Leaf` at the last component.
//! `lookup` walks from the ns root. `DevDir` is a real `vfs::Inode`:
//! `readdir` enumerates its BTreeMap children (sorted) THEN the ext4
//! overlay for its own path (skipping shadowed names), mirroring the
//! old `PrefixDirInode::readdir` offset/cookie bookkeeping.
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use crate::boot::dir_overlay;

/// A child of a `DevDir`: either a subdirectory or a registered leaf
/// inode (device node, symlink, static file).
enum DevEntry { Dir(Arc<DevDir>), Leaf(InodeRef) }

impl DevEntry {
    fn file_type(&self) -> FileType {
        match self { DevEntry::Dir(_) => FileType::Directory, DevEntry::Leaf(i) => i.file_type() }
    }
    fn as_inode(&self) -> InodeRef {
        match self { DevEntry::Dir(d) => Arc::clone(d) as InodeRef, DevEntry::Leaf(i) => Arc::clone(i) }
    }
}

/// A mutable directory in the devfs tree. Drivers register nodes at
/// runtime, so `children` is behind a spinlock. `path` is the dir's
/// absolute path (root = ""), used to drive the ext4 overlay.
pub struct DevDir {
    ino: Ino,
    path: String,
    children: Spinlock<BTreeMap<String, DevEntry>, TaskListClass>,
}

struct DevSymlink {
    ino: Ino,
    target: Vec<u8>,
}

impl Inode for DevSymlink {
    fn ino(&self) -> Ino { self.ino }
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> { Ok(self.target.clone()) }
}

/// Deterministic inode number from a path (FNV-1a, tagged into the
/// synthetic-dir range so it never collides with leaf inodes).
fn dir_ino(path: &str) -> Ino {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.as_bytes() { h ^= *b as u64; h = h.wrapping_mul(0x0000_0100_0000_01b3); }
    0x5000_0000_0000_0000 | (h & 0x0fff_ffff_ffff_ffff)
}

impl DevDir {
    fn new(path: String) -> Arc<DevDir> {
        let ino = if path.is_empty() { 0x5000_0001 } else { dir_ino(&path) };
        Arc::new(DevDir { ino, path, children: Spinlock::new(BTreeMap::new()) })
    }

    /// Get-or-create the subdirectory `name`, building its absolute path.
    fn child_dir(self: &Arc<DevDir>, name: &str) -> Arc<DevDir> {
        let mut g = self.children.lock();
        if let Some(DevEntry::Dir(d)) = g.get(name) { return Arc::clone(d); }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let d = DevDir::new(cp);
        g.insert(String::from(name), DevEntry::Dir(Arc::clone(&d)));
        d
    }

    /// Recursively deep-clone this dir (subdirs cloned, leaf Arcs shared).
    fn deep_clone(&self) -> Arc<DevDir> {
        let g = self.children.lock();
        let mut nc: BTreeMap<String, DevEntry> = BTreeMap::new();
        for (k, v) in g.iter() {
            let nv = match v {
                DevEntry::Dir(d) => DevEntry::Dir(d.deep_clone()),
                DevEntry::Leaf(i) => DevEntry::Leaf(Arc::clone(i)),
            };
            nc.insert(k.clone(), nv);
        }
        Arc::new(DevDir { ino: self.ino, path: self.path.clone(), children: Spinlock::new(nc) })
    }
}

impl Inode for DevDir {
    /// # C: O(1)
    fn ino(&self) -> Ino { self.ino }
    /// # C: O(1)
    fn fsid(&self) -> u64 { crate::DEVFS_FSID }
    /// # C: O(1)
    fn file_type(&self) -> FileType { FileType::Directory }
    /// # C: O(1)
    fn size(&self) -> u64 { 0 }
    /// # C: O(log children)
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let g = self.children.lock();
        g.get(name).map(|e| e.as_inode()).ok_or(VfsError::Enoent)
    }
    /// devtmpfs is mutable: systemd/tmpfiles create mountpoint dirs and
    /// runtime symlinks such as /dev/log during early boot.
    /// # C: O(log children)
    fn mkdir(&self, name: &str, _mode: u32) -> KResult<InodeRef> {
        let mut g = self.children.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let d = DevDir::new(cp);
        g.insert(String::from(name), DevEntry::Dir(Arc::clone(&d)));
        Ok(d as InodeRef)
    }
    /// # C: O(log children + target length)
    fn symlink_child(&self, name: &str, target: &[u8]) -> KResult<()> {
        let mut g = self.children.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let link = Arc::new(DevSymlink {
            ino: dir_ino(&cp),
            target: target.to_vec(),
        }) as InodeRef;
        g.insert(String::from(name), DevEntry::Leaf(link));
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
        // ext4 overlay for this dir's path, skipping synthetic-shadowed names.
        let mut ext4_seen: u64 = 0;
        let mut stopped = false;
        let mut stop_off: u64 = (idx as u64).max(r_len);
        // Root dir's overlay prefix is "/", not "".
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

/// Per-namespace tree roots. `ns == 0` is the init (host) namespace.
static ROOTS: Spinlock<BTreeMap<u64, Arc<DevDir>>, TaskListClass> = Spinlock::new(BTreeMap::new());

/// Get-or-create the root `DevDir` for namespace `ns` (path = "").
/// # C: O(log ns)
fn ns_root(ns: u64) -> Arc<DevDir> {
    let mut g = ROOTS.lock();
    if let Some(r) = g.get(&ns) { return Arc::clone(r); }
    let r = DevDir::new(String::new());
    g.insert(ns, Arc::clone(&r));
    r
}

/// Split an absolute path into non-empty components.
fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|c| !c.is_empty()).collect()
}

/// Register `full_path` → `inode` in namespace `ns`. Walks/creates the
/// intermediate `DevDir`s and inserts a `Leaf` at the last component.
/// Re-registration overwrites (matches old push-then-find-last).
/// # C: O(depth)
pub fn register(ns: u64, full_path: &str, inode: InodeRef) {
    let comps = components(full_path);
    if comps.is_empty() { return; }
    let mut dir = ns_root(ns);
    for c in &comps[..comps.len() - 1] { dir = dir.child_dir(c); }
    let leaf = comps[comps.len() - 1];
    // If a Dir already exists at this name (e.g. registering a node where
    // an intermediate dir was auto-created), keep the dir; a leaf at a dir
    // path is a registration conflict — prefer the leaf only if no dir.
    let mut g = dir.children.lock();
    match g.get(leaf) {
        Some(DevEntry::Dir(_)) => {}
        _ => { g.insert(String::from(leaf), DevEntry::Leaf(inode)); }
    }
}

/// Create the directory chain `path` as empty dirs — for mount points that
/// have no registered leaf children (e.g. `/sys/fs/cgroup`, where cgroupfs
/// mounts; without the dir the mount point can't be walked to and systemd's
/// `mkdir("/sys/fs/cgroup")` hits read-only `/sys/fs` instead of EEXIST).
/// # C: O(components)
pub fn register_dir(ns: u64, path: &str) {
    let comps = components(path);
    let mut dir = ns_root(ns);
    for c in &comps { dir = dir.child_dir(c); }
    let _ = dir;
}

/// Resolve `full_path` in namespace `ns`. A leaf encountered mid-path
/// → `None`; a dir as the final component → the dir as `InodeRef`; the
/// empty path → the ns root.
/// # C: O(depth)
pub fn lookup(ns: u64, full_path: &str) -> Option<InodeRef> {
    let comps = components(full_path);
    let root = {
        let g = ROOTS.lock();
        Arc::clone(g.get(&ns)?)
    };
    if comps.is_empty() { return Some(root as InodeRef); }
    let mut dir = root;
    for (i, c) in comps.iter().enumerate() {
        let g = dir.children.lock();
        match g.get(*c) {
            Some(DevEntry::Leaf(inode)) => {
                if i == comps.len() - 1 { return Some(Arc::clone(inode)); }
                return None; // leaf mid-path
            }
            Some(DevEntry::Dir(d)) => {
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

/// Remove the entry at `mount_point` (and its whole subtree, since
/// dropping the `Arc<DevDir>` drops its children) from namespace `ns`.
/// Returns 1 if an entry was removed, else 0.
/// # C: O(depth)
pub fn unregister_subtree(ns: u64, mount_point: &str) -> usize {
    let comps = components(mount_point);
    if comps.is_empty() { return 0; }
    let root = {
        let g = ROOTS.lock();
        match g.get(&ns) { Some(r) => Arc::clone(r), None => return 0 }
    };
    let mut dir = root;
    for c in &comps[..comps.len() - 1] {
        let next = { let g = dir.children.lock(); match g.get(*c) { Some(DevEntry::Dir(d)) => Arc::clone(d), _ => return 0 } };
        dir = next;
    }
    let leaf = comps[comps.len() - 1];
    if dir.children.lock().remove(leaf).is_some() { 1 } else { 0 }
}

/// Deep-clone the `src_ns` tree (dirs recursively cloned, leaf Arcs
/// shared) into `ROOTS[dst_ns]`. Used by clone(CLONE_NEWNS)/unshare.
/// # C: O(tree)
pub fn snapshot_ns(src_ns: u64, dst_ns: u64) {
    let src = {
        let g = ROOTS.lock();
        match g.get(&src_ns) { Some(r) => Arc::clone(r), None => return }
    };
    let cloned = src.deep_clone();
    ROOTS.lock().insert(dst_ns, cloned);
}
