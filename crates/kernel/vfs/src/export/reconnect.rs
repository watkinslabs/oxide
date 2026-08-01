// Reconnection: turning a decoded inode into a dentry that reaches the
// filesystem root.
//
// A decoded handle names an INODE. The dcache is a tree of `(parent, name)`
// nodes, so an inode with no cached dentry can only be wrapped in an anonymous,
// parentless alias — one whose path can never be rendered, which no `..` walk
// can leave, and which a second decode of the same object would duplicate. The
// fix is the upward walk: ask the filesystem for the object's parent, find the
// name the parent carries for it, repeat until an ancestor IS already in the
// tree, then instantiate the whole chain back down. That is a LOOP, not one
// hop: an object N levels below the last cached ancestor needs N steps, and a
// single step leaves everything above it still disconnected.
//
// A non-directory needs the same loop, applied to its PARENT: reconnecting the
// child under a parent that is itself disconnected just moves the problem up a
// level.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::dentry::Dentry;
use crate::dirent::DType;
use crate::file_ops::{DirContext, DirEmit};
use crate::inode::InodeRef;
use crate::superblock::SuperBlock;
use crate::types::{FileType, Ino};

/// Upward hops the reconnect walk takes before giving up.
///
/// A directory chain is bounded by the deepest path that can name it, and a
/// path component costs at least a separator plus a character, so
/// `PATH_MAX / 2` is above every reachable depth. The bound is what a `..`
/// chain that CYCLES (a corrupt image, an inode whose `..` points into its own
/// subtree) terminates on: without it the walk never reaches a connected
/// ancestor and never stops. Exceeding it is `ESTALE` at the caller, never a
/// half-reconnected dentry.
pub const MAX_RECONNECT_DEPTH: usize = crate::path::PATH_MAX / 2;

/// Does `d` reach the filesystem root through its parent chain (Linux
/// `dentry_connected`)?
///
/// The property `open_by_handle_at` owes its caller: a reopened fd whose dentry
/// is connected has a renderable path and a walkable `..`; a disconnected one
/// has neither. An anonymous alias is parentless and not a root, so it is never
/// connected — which is exactly why a decode that stops at the alias is
/// unfinished work.
/// # C: O(depth)
pub fn dentry_connected(d: &Arc<Dentry>) -> bool {
    let mut cur = d.clone();
    for _ in 0..MAX_RECONNECT_DEPTH {
        if cur.is_root() { return true; }
        match cur.parent() { Some(p) => cur = p.clone(), None => return false }
    }
    false
}

/// An alias of `inode` that is already connected, or `None`.
///
/// The reconnect walk's terminator: once an ancestor has one of these the
/// remaining work is downward instantiation, and for the decoded object itself
/// it means no walk is needed at all.
///
/// `s_root` is consulted by inode NUMBER, not by alias-list membership: the
/// root inode is built during fill-super, before the superblock it will belong
/// to exists, so it is not on any alias list — yet its dentry is the one
/// guaranteed-connected node every walk must be able to stop at.
/// # C: O(N_aliases * depth)
pub fn connected_alias(sb: &SuperBlock, inode: &InodeRef) -> Option<Arc<Dentry>> {
    if let Some(r) = sb.s_root() {
        if matches!(r.inode(), Some(i) if i.ino() == inode.ino()) { return Some(r); }
    }
    sb.i_aliases(inode.ino()).into_iter().find(|a| {
        matches!(a.inode(), Some(i) if Arc::ptr_eq(&i, inode)) && dentry_connected(a)
    })
}

/// Directory scan collecting the inode number `..` names.
struct DotDot {
    parent: Option<Ino>,
}

impl DirEmit for DotDot {
    fn emit(&mut self, name: &str, ino: u64, _d_type: FileType, _next_pos: u64) -> bool {
        if name == ".." { self.parent = Some(ino); return false; }
        true
    }
    fn emit_dt(&mut self, name: &str, ino: u64, _d_type: DType, next_pos: u64) -> bool {
        self.emit(name, ino, FileType::Directory, next_pos)
    }
}

/// `export_operations->get_parent`'s generic implementation: the directory
/// `dir`'s `..` entry names its parent, so read it and decode that number.
///
/// The generation is the unversioned wildcard because `..` names the CURRENT
/// parent — whatever incarnation is live now is by definition the right one,
/// and there is no older generation to compare against. `None` for a
/// non-directory, for a directory whose backend does not emit `..`, and for a
/// `..` naming an inode the filesystem cannot resolve.
///
/// A backend whose entries do not include the dots has no `..` to read: the VFS
/// synthesises those from the DENTRY, and a decoded inode is precisely the case
/// with no dentry to synthesise from. Such a filesystem must override the hook
/// with whatever records its hierarchy, or its directory handles reconnect only
/// while an ancestor is still cached.
/// # C: O(N_entries)
pub fn generic_get_parent(sb: &SuperBlock, dir: &InodeRef) -> Option<InodeRef> {
    if dir.file_type() != FileType::Directory { return None; }
    if !dir.i_fop().iterate_emits_dots() { return None; }
    let mut actor = DotDot { parent: None };
    let mut ctx = DirContext::new(0, &mut actor);
    let fop = dir.i_fop().clone();
    let _ = fop.iterate(dir, &mut ctx);
    sb.s_op.fh_to_dentry(sb, actor.parent?, super::GENERATION_ANY)
}

/// Make `inode` (a DIRECTORY) reach the filesystem root, returning its one
/// connected dentry — Linux `reconnect_path`.
///
/// Walks `get_parent` upward, recording the name each level carries, until an
/// ancestor already has a connected alias; then instantiates the recorded chain
/// back down from it. A directory has exactly one dentry, so the result IS the
/// directory's dentry — not a second alias for the same object.
///
/// `None` (`ESTALE` at the caller) when any level's parent cannot be decoded,
/// when a level's name is not in its parent (unlinked or renamed away since the
/// handle was minted), when a directory is its own parent without being a root,
/// or when the chain exceeds [`MAX_RECONNECT_DEPTH`]. Never a partially
/// reconnected dentry: the downward pass runs only after the upward walk found
/// a root.
/// # C: O(depth * N_entries)
pub fn reconnect_path(sb: &Arc<SuperBlock>, inode: &InodeRef) -> Option<Arc<Dentry>> {
    if inode.file_type() != FileType::Directory { return None; }
    let mut chain: Vec<(InodeRef, String)> = Vec::new();
    let mut cur = inode.clone();
    let mut anchor = None;
    for _ in 0..MAX_RECONNECT_DEPTH {
        if let Some(d) = connected_alias(sb, &cur) { anchor = Some(d); break; }
        let parent = sb.s_op.get_parent(sb, &cur)?;
        // A directory that is its own `..` is a filesystem root. Reaching one
        // WITHOUT a connected alias means the tree it roots was never published
        // (or the image is corrupt); either way no further hop can help.
        if parent.ino() == cur.ino() { return None; }
        let name = super::get_name(&parent, cur.ino())?;
        chain.push((cur.clone(), name));
        cur = parent;
    }
    let mut d = anchor?;
    for (i, name) in chain.iter().rev() {
        d = super::reconnect_child(&d, name, i)?;
    }
    Some(d)
}

/// Prefer an already-acceptable alias of the decoded inode over minting a fresh
/// disconnected one — Linux `find_acceptable_alias`.
///
/// A hardlinked file has one inode and several names; the decoded handle names
/// the inode, so any of those dentries answers it. Skipping this check would
/// reconnect a second dentry for an object the dcache already holds under a
/// perfectly good name, and would reject a caller whose reach covers one link
/// but not the one the handle happened to record.
///
/// `result` is tested first (Linux tests the freshly decoded dentry before the
/// alias list), then every OTHER live alias.
/// # C: O(N_aliases * cost of `acceptable`)
pub fn find_acceptable_alias<F>(sb: &SuperBlock, result: &Arc<Dentry>, acceptable: F)
    -> Option<Arc<Dentry>>
where F: Fn(&Arc<Dentry>) -> bool
{
    if acceptable(result) { return Some(result.clone()); }
    let ino = result.inode()?.ino();
    sb.i_aliases(ino).into_iter().find(|a| !Arc::ptr_eq(a, result) && acceptable(a))
}
