// dcache primitives per `fs/dcache.c` — the (parent,name)-keyed dentry
// cache. NO global path→dentry map: every primitive reaches a child only
// through its parent's per-SB `children` map keyed by component name.
//
// Linux analogs:
//   d_make_root      — alloc the root dentry, set sb->s_root
//   d_alloc          — NEGATIVE dentry (d_inode == None), not yet hashed
//   d_lookup         — rcu/hash read; Some(positive|negative) | None(uncached)
//   d_instantiate    — attach inode: negative -> positive
//   d_add            — d_alloc + d_instantiate + hash insert (race-safe)
//   d_add_negative   — cache a confirmed miss
//   dget / dput      — refcount via Arc strong count
//   d_move           — rename: rehome under a new (parent,name)
//   d_drop           — unhash from parent.children
//   d_splice_alias   — directory alias merge (positive child of a dir)

extern crate alloc;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::superblock::SuperBlock;

/// Allocate the root dentry for `sb` (no parent, empty name, positive)
/// and install it as `sb->s_root`. Records the root dentry as an alias of the
/// root inode (Linux `d_make_root` → `d_instantiate`). # C: O(1)
pub fn d_make_root(inode: InodeRef, sb: &Arc<SuperBlock>) -> Arc<Dentry> {
    let root = Dentry::new_root_in_sb(inode.clone(), sb);
    sb.set_s_root(root.clone());
    if let Some(s) = inode.i_sb() { s.i_add_alias(&inode, &root); }
    root
}

/// Allocate a NEGATIVE child dentry under `parent` (d_inode == None),
/// inheriting `parent`'s superblock. NOT inserted into the cache (Linux
/// `d_alloc` does not hash). # C: O(1)
pub fn d_alloc(parent: &Arc<Dentry>, name: &str) -> Arc<Dentry> {
    Dentry::new_child(parent, name, None)
}

/// Cache read: the child dentry for `name` under `parent`, positive OR
/// cached-negative. `None` = not cached (caller must do the slow
/// `i_op->lookup`). # C: O(log N_children)
pub fn d_lookup(parent: &Arc<Dentry>, name: &str) -> Option<Arc<Dentry>> {
    parent.cached_child(name)
}

/// Attach `inode` to a negative `dentry`, making it positive (post
/// create / lookup success), and record the dentry as an alias of the inode
/// in the owning SB's icache (Linux `d_instantiate` → `inode->i_dentry`).
/// # C: O(1)
pub fn d_instantiate(dentry: &Arc<Dentry>, inode: InodeRef) {
    if let Some(sb) = inode.i_sb() { sb.i_add_alias(&inode, dentry); }
    dentry.set_inode(Some(inode));
}

/// `d_alloc` + `d_instantiate` + hash-insert, race-safe: an existing
/// cached entry wins so all walkers share one dentry per (parent,name).
/// Records the (race-winning) dentry as an alias of `inode`.
/// # C: O(log N_children)
pub fn d_add(parent: &Arc<Dentry>, name: &str, inode: InodeRef) -> Arc<Dentry> {
    let child = Dentry::new_child(parent, name, Some(inode.clone()));
    let canon = parent.cache_child(name, child);
    if let Some(sb) = inode.i_sb() { sb.i_add_alias(&inode, &canon); }
    canon
}

/// Cache a confirmed miss as a negative dentry under `parent`. A later
/// `d_lookup` hit returns it so the walker can return `Enoent` WITHOUT
/// re-invoking `i_op->lookup`. # C: O(log N_children)
pub fn d_add_negative(parent: &Arc<Dentry>, name: &str) -> Arc<Dentry> {
    let child = Dentry::new_child(parent, name, None);
    parent.cache_child(name, child)
}

/// Take a reference (Linux `dget`). # C: O(1)
pub fn dget(d: &Arc<Dentry>) -> Arc<Dentry> { Arc::clone(d) }

/// Drop a reference (Linux `dput`). # C: O(1)
pub fn dput(d: Arc<Dentry>) { drop(d); }

/// Unhash `d` from its parent's children (Linux `d_drop` / `d_delete`):
/// a stale positive dentry isn't reused after unlink/rmdir/rename. Also drops
/// `d` from its inode's alias list (`inode->i_dentry`).
/// # C: O(log N_children)
pub fn d_drop(d: &Arc<Dentry>) {
    if let Some(inode) = d.inode() {
        if let Some(sb) = inode.i_sb() { sb.i_drop_alias(inode.ino(), d); }
    }
    if let Some(p) = d.parent() { p.forget_child(d.name()); }
}

/// Rename `old` to `(new_parent, new_name)` (Linux `d_move`). Unhashes
/// `old` from its current parent and rehomes its inode under the new
/// (parent,name) key, so `d_lookup(old_parent, old_name)` misses and
/// `d_lookup(new_parent, new_name)` hits.
/// # C: O(log N_children)
pub fn d_move(old: &Arc<Dentry>, new_parent: &Arc<Dentry>, new_name: &str) -> Arc<Dentry> {
    d_drop(old);
    match old.inode() {
        Some(inode) => d_add(new_parent, new_name, inode),
        None => d_add_negative(new_parent, new_name),
    }
}

/// Directory alias merge (Linux `d_splice_alias`): attach `inode` to the
/// dentry, returning the now-positive dentry. The full disconnected-alias
/// reattach (real dir hardlink resolution) is WP-pending; this handles
/// the common negative→positive splice. # C: O(1)
pub fn d_splice_alias(inode: InodeRef, d: &Arc<Dentry>) -> Arc<Dentry> {
    d_instantiate(d, inode); // records the i_dentry alias
    d.clone()
}
