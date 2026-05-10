// Pseudo-FS primitive shared by `19§3` (procfs / sysfs / devfs).
//
// The kernel exposes three pseudo file systems whose contents are
// generated on demand from kernel state. They share the same shape:
// a tree of named directories holding leaf files; each leaf reads
// (and optionally writes) via a `PseudoOps` callback. This module is
// the shared core; per-FS surface (`/proc/<pid>/...`, `/sys/...`,
// `/dev/<n>`) lands as separate consumers atop it.
//
// Out of scope: VFS Inode integration (the `Inode` trait wraps
// `PseudoEntry` once the dentry-cache lands per `16§4`), sysfs KObj
// release callbacks, devfs DevId multiplexing, and per-pid procfs
// dynamism (the entry "exists" predicate becomes a sched-driven
// query once `13` lands more thoroughly).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Inode as InodeClass, RwLock};

/// Pseudo-FS error type. Numeric reps Linux-aligned.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PseudoError {
    Eperm   = 1,
    Enoent  = 2,
    Eexist  = 17,
    Enotdir = 20,
    Eisdir  = 21,
    Einval  = 22,
}

pub type KResult<T> = core::result::Result<T, PseudoError>;

/// Read/write callback per `19§3`. `read` snapshots data per
/// invariant 4 (`19§2`); writes are optional (most pseudo files are
/// read-only) — defaulting `write` to `Eperm` keeps the safe path
/// the default.
pub trait PseudoOps: Send + Sync {
    /// # C: depends on producer
    fn read(&self) -> Vec<u8>;

    /// # C: depends on producer
    fn write(&self, _buf: &[u8]) -> KResult<usize> { Err(PseudoError::Eperm) }
}

/// Concrete leaf node: name, mode bits, callback.
pub struct PseudoLeaf {
    pub name: String,
    pub mode: u32,
    pub ops:  Arc<dyn PseudoOps>,
}

#[derive(Default)]
struct PseudoDir {
    entries: BTreeMap<String, PseudoEntry>,
}

enum PseudoEntry {
    Dir(PseudoDir),
    Leaf(Arc<PseudoLeaf>),
}

/// Tree-shaped pseudo-FS. Single RwLock guards the entire tree —
/// `19§3` traffic is dominated by short-lived reads, and the cache
/// per-entry shape lands once VFS `Inode` integration does.
pub struct PseudoFs {
    inner: RwLock<PseudoDir, InodeClass>,
}

impl PseudoFs {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: RwLock::new(PseudoDir { entries: BTreeMap::new() }) }
    }

    /// Create the directory hierarchy at `path`. Each missing component
    /// is created; an existing non-directory at any prefix is `Enotdir`.
    /// `mkdir("/a/b/c")` after `mkdir("/a/b")` is idempotent.
    /// # C: O(components)
    pub fn mkdir(&self, path: &str) -> KResult<()> {
        let parts = split_path(path)?;
        let mut tree = self.inner.write();
        let mut cur: &mut PseudoDir = &mut tree;
        for comp in parts {
            let owned = comp.to_string();
            match cur.entries.entry(owned) {
                alloc::collections::btree_map::Entry::Vacant(v) => {
                    let dir = v.insert(PseudoEntry::Dir(PseudoDir::default()));
                    if let PseudoEntry::Dir(d) = dir { cur = d; } else { unreachable!() }
                }
                alloc::collections::btree_map::Entry::Occupied(o) => {
                    let entry = o.into_mut();
                    match entry {
                        PseudoEntry::Dir(d)  => cur = d,
                        PseudoEntry::Leaf(_) => return Err(PseudoError::Enotdir),
                    }
                }
            }
        }
        Ok(())
    }

    /// Install `leaf` at `parent_path/leaf.name`. Parent must exist
    /// and be a directory. Returns `Eexist` on collision (whether
    /// against another leaf or a sub-directory).
    /// # C: O(components)
    pub fn register(&self, parent_path: &str, leaf: PseudoLeaf) -> KResult<()> {
        let parts = split_path(parent_path)?;
        let mut tree = self.inner.write();
        let cur = walk_mut(&mut tree, &parts)?;
        let name = leaf.name.clone();
        if cur.entries.contains_key(&name) {
            return Err(PseudoError::Eexist);
        }
        cur.entries.insert(name, PseudoEntry::Leaf(Arc::new(leaf)));
        Ok(())
    }

    /// Remove the entry at `path` (leaf or empty directory). Returns
    /// `Enoent` if missing, `Enotempty`-equivalent (`Einval`) if the
    /// target is a non-empty directory.
    /// # C: O(components)
    pub fn unregister(&self, path: &str) -> KResult<()> {
        let parts = split_path(path)?;
        if parts.is_empty() { return Err(PseudoError::Einval); }
        let (last, prefix) = parts.split_last().expect("checked non-empty");
        let mut tree = self.inner.write();
        let cur = walk_mut(&mut tree, prefix)?;
        match cur.entries.get(*last) {
            None => Err(PseudoError::Enoent),
            Some(PseudoEntry::Dir(d)) if !d.entries.is_empty() => Err(PseudoError::Einval),
            _ => {
                cur.entries.remove(*last);
                Ok(())
            }
        }
    }

    /// Snapshot the leaf at `path` and call its `read`.
    /// # C: O(components) plus `read` cost
    pub fn read(&self, path: &str) -> KResult<Vec<u8>> {
        let parts = split_path(path)?;
        if parts.is_empty() { return Err(PseudoError::Eisdir); }
        let leaf = {
            let tree = self.inner.read();
            let (last, prefix) = parts.split_last().unwrap();
            let dir = walk_ref(&tree, prefix)?;
            match dir.entries.get(*last) {
                Some(PseudoEntry::Leaf(l)) => Arc::clone(l),
                Some(PseudoEntry::Dir(_))  => return Err(PseudoError::Eisdir),
                None                       => return Err(PseudoError::Enoent),
            }
        };
        Ok(leaf.ops.read())
    }

    /// Forward `write` to the leaf at `path`. Returns whatever the
    /// callback returns (typically bytes accepted, or `Eperm` for a
    /// read-only leaf).
    /// # C: O(components) plus `write` cost
    pub fn write(&self, path: &str, buf: &[u8]) -> KResult<usize> {
        let parts = split_path(path)?;
        if parts.is_empty() { return Err(PseudoError::Eisdir); }
        let leaf = {
            let tree = self.inner.read();
            let (last, prefix) = parts.split_last().unwrap();
            let dir = walk_ref(&tree, prefix)?;
            match dir.entries.get(*last) {
                Some(PseudoEntry::Leaf(l)) => Arc::clone(l),
                Some(PseudoEntry::Dir(_))  => return Err(PseudoError::Eisdir),
                None                       => return Err(PseudoError::Enoent),
            }
        };
        leaf.ops.write(buf)
    }

    /// List entries at `path`. Returns names only, sorted.
    /// # C: O(components + N) — N = entries at the dir
    pub fn list(&self, path: &str) -> KResult<Vec<String>> {
        let parts = split_path(path)?;
        let tree = self.inner.read();
        let dir = walk_ref(&tree, &parts)?;
        Ok(dir.entries.keys().cloned().collect())
    }

    /// True iff `path` resolves to an existing entry (leaf or directory).
    /// # C: O(components)
    pub fn exists(&self, path: &str) -> bool {
        let parts = match split_path(path) {
            Ok(p) => p,
            Err(_) => return false,
        };
        if parts.is_empty() { return true; }
        let tree = self.inner.read();
        let (last, prefix) = parts.split_last().unwrap();
        let dir = match walk_ref(&tree, prefix) { Ok(d) => d, Err(_) => return false };
        dir.entries.contains_key(*last)
    }
}

impl Default for PseudoFs {
    fn default() -> Self { Self::new() }
}

fn split_path(path: &str) -> KResult<Vec<&str>> {
    if path.is_empty() { return Err(PseudoError::Einval); }
    let stripped = path.strip_prefix('/').unwrap_or(path);
    Ok(stripped.split('/').filter(|s| !s.is_empty() && *s != ".").collect())
}

fn walk_ref<'a>(root: &'a PseudoDir, parts: &[&str]) -> KResult<&'a PseudoDir> {
    let mut cur = root;
    for c in parts {
        match cur.entries.get(*c) {
            Some(PseudoEntry::Dir(d))  => cur = d,
            Some(PseudoEntry::Leaf(_)) => return Err(PseudoError::Enotdir),
            None                       => return Err(PseudoError::Enoent),
        }
    }
    Ok(cur)
}

fn walk_mut<'a>(root: &'a mut PseudoDir, parts: &[&str]) -> KResult<&'a mut PseudoDir> {
    let mut cur = root;
    for c in parts {
        match cur.entries.get_mut(*c) {
            Some(PseudoEntry::Dir(d))  => cur = d,
            Some(PseudoEntry::Leaf(_)) => return Err(PseudoError::Enotdir),
            None                       => return Err(PseudoError::Enoent),
        }
    }
    Ok(cur)
}

/// Simple `PseudoOps` backed by a static byte slice — useful for
/// constants like `/proc/version` whose contents don't change.
pub struct StaticBytesOps(pub &'static [u8]);

impl PseudoOps for StaticBytesOps {
    fn read(&self) -> Vec<u8> { self.0.to_vec() }
}

/// `PseudoOps` backed by a closure producing fresh bytes on every read
/// — for `/proc/uptime` and friends whose value changes per call.
pub struct DynamicOps<F>(pub F)
where
    F: Fn() -> Vec<u8> + Send + Sync + 'static;

impl<F> PseudoOps for DynamicOps<F>
where
    F: Fn() -> Vec<u8> + Send + Sync + 'static,
{
    fn read(&self) -> Vec<u8> { (self.0)() }
}
