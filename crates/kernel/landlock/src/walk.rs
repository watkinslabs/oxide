// Hierarchy walk. Rights are tied to hierarchies, so every check has to visit
// the object and each of its ancestors up to the namespace root, crossing
// mount points the same way `..` does. Stopping at a mount boundary would drop
// every rule anchored above it.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{Dentry, InodeRef, VfsPath};

/// One visited hierarchy node. `inode` is the rule key: rules are tied to the
/// object, so the same directory reached through a bind mount matches.
#[derive(Clone)]
pub struct Node {
    pub mnt_id: u64,
    pub dentry: Arc<Dentry>,
    pub inode:  InodeRef,
}

/// Bound on one walk. A cycle in the dentry parent chain would otherwise hang
/// a syscall with interrupts off.
const MAX_WALK: usize = 4096;

/// Object-to-root chain, nearest first.
/// # C: O(depth)
pub fn ancestors(path: &VfsPath) -> Vec<Node> {
    from(path.mnt_id, path.dentry.clone())
}

/// Chain starting at an explicit `(mnt_id, dentry)`.
/// # C: O(depth)
pub fn from(mnt_id: u64, dentry: Arc<Dentry>) -> Vec<Node> {
    let mut out = Vec::new();
    let mut mnt = mnt_id;
    let mut d = dentry;
    for _ in 0..MAX_WALK {
        if let Some(i) = d.inode() { out.push(Node { mnt_id: mnt, dentry: d.clone(), inode: i }); }
        if at_mount_root(mnt, &d) {
            match vfs::mount::mountpoint_of(mnt) {
                Some((mp, parent)) => { d = mp; mnt = parent; continue; }
                None => break,
            }
        }
        match d.parent() { Some(p) => { let p = p.clone(); d = p; } None => break }
    }
    out
}

/// Chain from `dentry` up to (and including) `stop`, without crossing mounts.
/// Used where the caller already knows the common ancestor of two hierarchies.
/// # C: O(depth)
pub fn up_to(mnt_id: u64, dentry: Arc<Dentry>, stop: &Arc<Dentry>) -> Vec<Node> {
    let mut out = Vec::new();
    let mut d = dentry;
    for _ in 0..MAX_WALK {
        if let Some(i) = d.inode() { out.push(Node { mnt_id, dentry: d.clone(), inode: i }); }
        if Arc::ptr_eq(&d, stop) { break; }
        match d.parent() { Some(p) => { let p = p.clone(); d = p; } None => break }
    }
    out
}

/// # C: O(log N_mounts)
pub fn at_mount_root(mnt_id: u64, d: &Arc<Dentry>) -> bool {
    match vfs::mount::root_dentry_for_mount_id(mnt_id) {
        Some(r) => Arc::ptr_eq(&r, d),
        None => false,
    }
}

/// Common ancestor of any two paths reached through the same mount: the mount's
/// own root, or the top of the dentry tree when the path is not reached through
/// a registered mount.
/// # C: O(log N_mounts + depth)
pub fn mount_root(mnt_id: u64, d: &Arc<Dentry>) -> Arc<Dentry> {
    if let Some(r) = vfs::mount::root_dentry_for_mount_id(mnt_id) { return r; }
    let mut cur = d.clone();
    for _ in 0..MAX_WALK {
        match cur.parent() { Some(p) => { let p = p.clone(); cur = p; } None => break }
    }
    cur
}
