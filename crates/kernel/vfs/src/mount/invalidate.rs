//! Stale-negative-dentry invalidation for create paths that BYPASS namei
//! (`docs/16§4`). namei's `vfs_create`/`vfs_mknod` thread the child dentry and
//! `d_instantiate` it, so a create there flips the cached negative to positive.
//! But a create driven straight off the parent *inode* op — AF_UNIX `bind(2)`
//! materialising an `S_IFSOCK` node via `mknod_child`, and any other
//! inode-op-direct materialiser — never touches the dcache. A NEGATIVE dentry
//! left by an earlier failed lookup then shadows the new node forever: the
//! namei walk treats a cached negative as DEFINITIVE ENOENT (`namei/walk.rs`),
//! so `stat(path)` keeps returning ENOENT while `readdir` shows the child.
//! `drop_stale_negative` re-syncs the dcache after such a create. Split out of
//! `mount.rs` to hold the line cap; parent state reached via `super::`.

use super::*;

/// Drop a cached NEGATIVE dentry at absolute `abs` so the next lookup re-reads
/// the parent dir and instantiates a positive dentry. No-op if nothing is
/// cached, or the cached dentry is already positive, or the parent can't be
/// resolved. Call AFTER an inode-op-direct create (e.g. `mknod_child`) that
/// bypassed namei's `d_instantiate`. # C: O(components)
pub fn drop_stale_negative(abs: &str) {
    let Some(base) = global_root() else { return; };
    let rel = abs.trim_start_matches('/');
    let (parents, last) = match rel.rsplit_once('/') {
        Some((p, n)) => (p, n),
        None => ("", rel),
    };
    if last.is_empty() { return; }
    let parent = if parents.is_empty() { base } else { match super::descend(&base, parents) { Some(d) => d, None => return } };
    if let Some(d) = crate::dcache::d_lookup(&parent, last) {
        if d.is_negative() { crate::dcache::d_drop(&d); }
    }
}
