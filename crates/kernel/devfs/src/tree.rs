//! Per-namespace devfs directory tree (Linux devtmpfs shape), now backed by
//! the generic `kernfs::PseudoDir` (D1b). Each namespace owns an
//! `Arc<PseudoDir>` root (path = ""); `register` walks/creates intermediate
//! dirs and inserts a `Leaf` at the last component, `lookup` walks from the
//! ns root, `readdir` enumerates children (sorted) THEN the ext4 overlay for
//! the dir's own path. devfs's tree keeps `overlay = true` on every dir so
//! `/dev` + `/etc` synthetic nodes merge with the on-disk rootfs exactly as
//! before. The `DevDir`/`DevSymlink` inodes were lifted verbatim into
//! `kernfs::{PseudoDir, PseudoSymlink}`.
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use kernfs::PseudoDir;
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::InodeRef;

/// Per-namespace tree roots. `ns == 0` is the init (host) namespace.
static ROOTS: Spinlock<BTreeMap<u64, Arc<PseudoDir>>, TaskListClass> = Spinlock::new(BTreeMap::new());

/// Get-or-create the root `PseudoDir` for namespace `ns` (path = "").
/// devfs dirs overlay the ext4 rootfs (`/dev`, `/etc`), so `overlay = true`.
/// # C: O(log ns)
fn ns_root(ns: u64) -> Arc<PseudoDir> {
    let mut g = ROOTS.lock();
    if let Some(r) = g.get(&ns) { return Arc::clone(r); }
    let r = PseudoDir::new_root(0x5000_0001, crate::DEVFS_FSID, true);
    g.insert(ns, Arc::clone(&r));
    r
}

/// Register `full_path` → `inode` in namespace `ns`. # C: O(depth)
pub fn register(ns: u64, full_path: &str, inode: InodeRef) {
    ns_root(ns).insert_path(full_path, inode);
}

/// Create the directory chain `path` as empty dirs (mount points without
/// registered leaves, e.g. `/sys/fs/cgroup`). # C: O(components)
pub fn register_dir(ns: u64, path: &str) {
    ns_root(ns).ensure_dir_path(path);
}

/// Resolve `full_path` in namespace `ns`. Leaf mid-path → `None`; dir as the
/// final component → the dir; empty path → the ns root. # C: O(depth)
pub fn lookup(ns: u64, full_path: &str) -> Option<InodeRef> {
    let root = {
        let g = ROOTS.lock();
        Arc::clone(g.get(&ns)?)
    };
    root.lookup_path(full_path)
}

/// Remove the entry at `mount_point` (and its subtree) from namespace `ns`.
/// Returns 1 if an entry was removed, else 0. # C: O(depth)
pub fn unregister_subtree(ns: u64, mount_point: &str) -> usize {
    let root = {
        let g = ROOTS.lock();
        match g.get(&ns) { Some(r) => Arc::clone(r), None => return 0 }
    };
    root.remove_subtree(mount_point)
}

/// Deep-clone the `src_ns` tree (dirs recursively cloned, leaf Arcs shared)
/// into `ROOTS[dst_ns]`. Used by clone(CLONE_NEWNS)/unshare. # C: O(tree)
pub fn snapshot_ns(src_ns: u64, dst_ns: u64) {
    let src = {
        let g = ROOTS.lock();
        match g.get(&src_ns) { Some(r) => Arc::clone(r), None => return }
    };
    let cloned = src.deep_clone();
    ROOTS.lock().insert(dst_ns, cloned);
}
