//! Per-namespace devfs directory tree (Linux devtmpfs shape), backed by the
//! generic `kernfs::PseudoDir` (D1b). DEVFS-PRIVATE as of D1d: this tree holds
//! ONLY devfs's own content — `/dev` (devtmpfs nodes) + the `/etc` overlay.
//! procfs (`/proc`) and sysfs (`/sys`) own their OWN `PseudoDir` roots now
//! (D1c/D1d); this is no longer a shared cross-filesystem path registry.
//! Each namespace owns an `Arc<PseudoDir>` root (path = ""); `register`
//! walks/creates intermediate dirs and inserts a `Leaf` at the last component,
//! `lookup` walks from the ns root, `readdir` enumerates children (sorted)
//! THEN the ext4 overlay for the dir's own path. `overlay = true` on every dir
//! so `/dev` + `/etc` synthetic nodes merge with the on-disk rootfs. The
//! ns-keyed `ROOTS` map is RETAINED (not collapsed to a single root): it is
//! load-bearing for mount-namespace `/dev` — `snapshot_ns` (CLONE_NEWNS, used
//! by unshare 272/F119) deep-clones the per-ns `/dev`, `unregister_subtree`
//! (umount2 166) detaches a per-ns mount point; collapsing to one root would
//! regress private `/dev` in a mount namespace. Devtmpfs is ONE shared
//! instance in Linux, so `register`/`register_dir` for ns0 (every boot node +
//! every runtime `add_device_node`) BROADCAST into ns0 + all snapshot'd roots:
//! a node registered AFTER an unshare (e.g. `/dev/input/event0`,
//! `/dev/dri/card0` when virtio input/gpu probes late) still appears in every
//! namespace's `/dev`. `unregister_subtree_all` (device_del/hot-unplug) removes
//! from every root; `unregister_subtree` (umount2) stays per-ns. The
//! `DevDir`/`DevSymlink`
//! inodes were lifted verbatim into `kernfs::{PseudoDir, PseudoSymlink}`.
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kernfs::PseudoDir;
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::InodeRef;

/// Per-namespace tree roots. `ns == 0` is the init (host) namespace.
static ROOTS: Spinlock<BTreeMap<u64, Arc<PseudoDir>>, TaskListClass> = Spinlock::new(BTreeMap::new());

/// Get-or-create the root `PseudoDir` for namespace `ns` (path = "").
/// D17/D19: devfs no longer overlays the ext4 rootfs at all. `/dev` is FULLY
/// populated by `drv::try_device_add` + the boot `register`/`register_dir` nodes
/// (the rootfs image ships ZERO `/dev` device nodes), and `/etc`'s 7 former
/// runtime-synthetic files now ship as real rootfs ext4 files
/// (`tools/xtask/src/rootfs_etc.rs`), so the directory-overlay machinery is
/// gone. # C: O(log ns)
fn ns_root(ns: u64) -> Arc<PseudoDir> {
    let mut g = ROOTS.lock();
    if let Some(r) = g.get(&ns) { return Arc::clone(r); }
    let r = PseudoDir::new_root(0x5000_0001, crate::DEVFS_FSID);
    g.insert(ns, Arc::clone(&r));
    r
}

/// Snapshot every namespace root as `Arc` clones, first ensuring ns0 exists.
/// Roots are collected under the `ROOTS` lock then returned, so callers mutate
/// each tree WITHOUT holding `ROOTS` (avoids nesting the `ROOTS` spinlock under
/// the kernfs child-map spinlock). # C: O(ns)
fn all_roots_ensure0() -> Vec<Arc<PseudoDir>> {
    let mut g = ROOTS.lock();
    if !g.contains_key(&0) {
        let r = PseudoDir::new_root(0x5000_0001, crate::DEVFS_FSID);
        g.insert(0, r);
    }
    g.values().map(Arc::clone).collect()
}

/// Register `full_path` → `inode` in namespace `ns`. For the init namespace
/// (`ns == 0` — every boot node and every `add_device_node` runtime node) the
/// registration is BROADCAST into ns0 + all snapshot'd namespace roots: Linux
/// devtmpfs is ONE shared instance, so a node registered AFTER a mount-ns split
/// (e.g. `/dev/input/event0`, `/dev/dri/card0` when the virtio input/gpu driver
/// probes at t≈10s, long after systemd/udev workers `unshare(CLONE_NEWNS)`) is
/// still visible in every namespace's `/dev` — they all view the same
/// superblock. The shared leaf `InodeRef` is cloned into each root, matching the
/// single-devtmpfs-inode identity. An explicit non-zero `ns` targets that ns
/// only (private-`/dev` construction). # C: O(ns·depth)
pub fn register(ns: u64, full_path: &str, inode: InodeRef) {
    if ns == 0 {
        for r in all_roots_ensure0() { r.insert_path(full_path, InodeRef::clone(&inode)); }
    } else {
        ns_root(ns).insert_path(full_path, inode);
    }
}

/// Create the directory chain `path` as empty dirs (mount points without
/// registered leaves, e.g. `/dev/shm`, `/dev/pts`). Broadcast across all roots
/// for `ns == 0` for the same shared-devtmpfs reason as `register`. # C: O(ns·components)
pub fn register_dir(ns: u64, path: &str) {
    if ns == 0 {
        for r in all_roots_ensure0() { r.ensure_dir_path(path); }
    } else {
        ns_root(ns).ensure_dir_path(path);
    }
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

/// Remove the entry at `path` (and its subtree) from EVERY namespace root.
/// Device hot-unplug (`device_del` → `del_device_node`) removes the node from
/// the single shared devtmpfs instance, so it must vanish from all namespaces —
/// unlike per-ns `unregister_subtree` (umount2), which detaches ONE ns's mount.
/// Returns the summed count removed. # C: O(ns·depth)
pub fn unregister_subtree_all(path: &str) -> usize {
    let roots: Vec<Arc<PseudoDir>> = {
        let g = ROOTS.lock();
        g.values().map(Arc::clone).collect()
    };
    let mut n = 0;
    for r in roots { n += r.remove_subtree(path); }
    n
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

#[cfg(test)]
mod ns_visibility_tests {
    use super::*;

    // Distinct high ns ids + distinct paths per test: `ROOTS` is a process-global
    // static and cargo runs tests concurrently, so tests must not share ns ids or
    // node paths. Any incidental cross-test broadcast lands on a path we don't
    // assert, so it is harmless.

    /// THE `/dev/input/event0`-after-unshare scenario: a udev worker
    /// `unshare(CLONE_NEWNS)`s (snapshot_ns) at boot, THEN the virtio input
    /// driver probes late and registers the node into ns0 only. Real devtmpfs is
    /// one shared instance, so the node must be visible in the child ns's `/dev`.
    #[test]
    fn runtime_node_after_snapshot_is_visible_in_child_ns() {
        let child = 0x5_1b0_0000u64;
        snapshot_ns(0, child); // worker unshares before the device probes
        register(0, "/dev/input/s1b_event0", crate::misc::make_null_inode()); // late probe, ns0
        assert!(lookup(child, "/dev/input/s1b_event0").is_some(),
            "runtime-registered node visible in child mount ns (devtmpfs is shared)");
        assert!(lookup(0, "/dev/input/s1b_event0").is_some(), "and in ns0");
    }

    /// Per-ns umount (umount2 → `unregister_subtree`) detaches ONLY the target
    /// ns; other namespaces and ns0 keep the node. Broadcast add must not break
    /// the private-detach the tree.rs module comment guards.
    #[test]
    fn umount_detaches_only_target_ns() {
        let a = 0x5_1b1_0000u64;
        let b = 0x5_1b2_0000u64;
        register(0, "/dev/s1b_card0", crate::misc::make_null_inode());
        snapshot_ns(0, a);
        snapshot_ns(0, b);
        assert!(lookup(a, "/dev/s1b_card0").is_some());
        assert!(lookup(b, "/dev/s1b_card0").is_some());
        assert_eq!(unregister_subtree(a, "/dev/s1b_card0"), 1, "detach in ns a");
        assert!(lookup(a, "/dev/s1b_card0").is_none(), "gone in ns a");
        assert!(lookup(b, "/dev/s1b_card0").is_some(), "still present in ns b");
        assert!(lookup(0, "/dev/s1b_card0").is_some(), "still present in ns0");
    }

    /// Device hot-unplug (`del_device_node` → `unregister_subtree_all`) removes
    /// the node from EVERY namespace, unlike per-ns umount.
    #[test]
    fn hotunplug_removes_from_all_ns() {
        let a = 0x5_1b3_0000u64;
        register(0, "/dev/s1b_hot0", crate::misc::make_null_inode());
        snapshot_ns(0, a);
        assert!(lookup(a, "/dev/s1b_hot0").is_some());
        let removed = unregister_subtree_all("/dev/s1b_hot0");
        assert!(removed >= 2, "removed from at least ns0 + ns a, got {}", removed);
        assert!(lookup(0, "/dev/s1b_hot0").is_none(), "gone in ns0");
        assert!(lookup(a, "/dev/s1b_hot0").is_none(), "gone in ns a");
    }
}
