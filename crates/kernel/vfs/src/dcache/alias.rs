extern crate alloc;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::FileType;

use super::alloc::d_instantiate;
use super::hash::DENTRY_HASHTABLE;
use super::rename::d_move;

/// Obtain a dentry referring to `inode` without a path/parent (Linux
/// `d_obtain_alias`). Reuses an existing live alias before allocating a new
/// disconnected anonymous alias. # C: O(N_aliases)
pub fn d_obtain_alias(inode: InodeRef) -> Arc<Dentry> {
    if let Some(sb) = inode.i_sb() {
        if let Some(existing) = sb.i_aliases(inode.ino()).into_iter().next() { return existing; }
    }
    let anon = Dentry::new_anon(inode.clone());
    if let Some(sb) = inode.i_sb() { sb.i_add_alias(&inode, &anon); }
    anon.grab_inode_hold(); // D3/D37: anonymous alias counts its inode hold
    anon
}

/// Directory alias merge (Linux `d_splice_alias`): splice `inode` into the
/// negative dentry `d` at `(d.parent, d.name)` and return the now-positive
/// dentry. Enforces the directory single-dentry invariant: a directory inode
/// has at most ONE dentry, so if `inode` already carries a `D_DISCONNECTED`
/// anonymous alias (from `d_obtain_alias` / exportfs `open_by_handle_at`),
/// that anon alias IS the directory's real dentry — reattach it to
/// `(d.parent, d.name)` and return that, instead of instantiating `d` (a
/// second positive dir dentry would split the dcache subtree). Linux
/// `__d_find_alias` + `__d_move`. Non-directories, and dirs with no prior
/// alias, take the common negative→positive splice. # C: O(N_aliases)
pub fn d_splice_alias(inode: InodeRef, d: &Arc<Dentry>) -> Arc<Dentry> {
    if inode.file_type() == FileType::Directory {
        if let (Some(sb), Some(parent)) = (inode.i_sb(), d.parent()) {
            let anon = sb.i_aliases(inode.ino()).into_iter()
                .find(|a| a.is_disconnected() && !Arc::ptr_eq(a, d));
            if let Some(alias) = anon {
                // Reattach the disconnected dir alias under (parent, d.name):
                // d_move unhashes/forgets `alias`, then re-keys `inode` at the
                // new (parent,name) so it is the sole connected dir dentry.
                return d_move(&alias, parent, d.name());
            }
        }
    }
    d_instantiate(d, inode);
    if !d.is_hashed() { DENTRY_HASHTABLE.insert(d); }
    d.clone()
}
