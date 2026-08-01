//! `s_export_op` — the exportable-file-handle backend (`16`).
//!
//! `name_to_handle_at(2)` encodes an object's identity; `open_by_handle_at(2)`
//! turns that identity back into a dentry WITHOUT a path walk. Two properties
//! the naive "inode number only" handle cannot provide, and this module owns:
//!
//!   * **Recycle safety.** An inode number alone is not an identity: the moment
//!     a filesystem frees and reallocates it the old handle silently names a
//!     DIFFERENT file. The handle therefore carries `(ino, i_generation)` and
//!     decode rejects a generation mismatch with `ESTALE`.
//!   * **Reconnection.** A decoded non-directory would otherwise be a
//!     disconnected alias with no name and no parent. A connectable handle
//!     carries the parent's `(ino, generation)` as well, and decode re-derives
//!     the child's name inside that parent so the returned dentry is a real
//!     `(parent, name)` cache entry.
//!
//! The backend hooks live on [`crate::SuperOps`] (`fh_to_dentry`/`fh_to_parent`)
//! — the same vtable that owns `statfs`/`evict_inode` — so there is one owner
//! per superblock and no side registry keyed on anything else.

extern crate alloc;

//
// Module manifest:
//   fid — the FID payload this kernel encodes and its codec, shared by
//         `name_to_handle_at`/`open_by_handle_at` and by fanotify's
//         `FAN_REPORT_FID` info records, which must encode the SAME handle or
//         a fid a watcher was handed cannot be opened.

pub mod fid;

use alloc::string::String;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::dirent::DType;
use crate::file_ops::{DirContext, DirEmit};
use crate::inode::{Inode, InodeRef};
use crate::types::{FileType, Ino};

/// Generation value meaning "this filesystem does not version its inode
/// numbers". A handle encoding it matches any generation, which is what a
/// pseudo-filesystem that never recycles a number needs; a filesystem that
/// DOES recycle (any on-disk one) stamps a nonzero generation and gets the
/// strict comparison.
pub const GENERATION_ANY: u32 = 0;

/// Does a handle's encoded generation name this inode's incarnation?
///
/// A zero on either side is the "unversioned" wildcard above; two nonzero
/// values must be equal. Mismatch is `ESTALE` at the caller, never a
/// successful open of the recycled object.
/// # C: O(1)
pub fn generation_matches(inode: &Inode, encoded: u32) -> bool {
    let have = inode.i_generation();
    encoded == GENERATION_ANY || have == GENERATION_ANY || have == encoded
}

/// Resolve `ino` on `sb` from the inode cache alone, honoring the encoded
/// generation. The [`crate::SuperOps::fh_to_dentry`] default builds on this;
/// a filesystem with a backing store overrides the hook so an EVICTED inode
/// still resolves (re-read from the store) instead of reporting `ESTALE`.
/// # C: O(log N_ino)
pub fn ilookup_generation(sb: &crate::SuperBlock, ino: Ino, generation: u32) -> Option<InodeRef> {
    let inode = sb.ilookup(ino)?;
    if generation_matches(&inode, generation) { Some(inode) } else { None }
}

/// Wrap a decoded inode in a dentry with no name (Linux `d_obtain_alias`).
/// Reuses a live alias when the inode already has one, so a decoded handle to
/// an object that IS in the tree yields its real, named dentry.
/// # C: O(N_aliases)
pub fn fh_alias(inode: InodeRef) -> Arc<Dentry> { crate::dcache::d_obtain_alias(inode) }

/// Directory scan collecting the name whose entry points at `want`.
struct NameOf {
    want: Ino,
    found: Option<String>,
}

impl DirEmit for NameOf {
    fn emit(&mut self, name: &str, ino: u64, _d_type: FileType, _next_pos: u64) -> bool {
        // `.` and `..` name the directory and its parent, never a child, so a
        // hardlinked child that happens to share the scanned directory's ino
        // (impossible on a sane fs, but a corrupt image can claim it) cannot
        // make the reconnect return "." as the child's name.
        if name == "." || name == ".." { return true; }
        if ino == self.want { self.found = Some(String::from(name)); return false; }
        true
    }
    fn emit_dt(&mut self, name: &str, ino: u64, _d_type: DType, next_pos: u64) -> bool {
        self.emit(name, ino, FileType::Regular, next_pos)
    }
}

/// `export_operations->get_name`'s generic implementation: read `parent` and
/// return the name its entry for `child_ino` carries.
///
/// This is the step that turns a decoded connectable handle into a CONNECTED
/// dentry: without a name there is no `(parent, name)` cache key and the
/// reopened fd's path can never be rendered. `None` means the child is no
/// longer an entry of that parent (unlinked, or renamed elsewhere since the
/// handle was minted) — `ESTALE` at the caller, not a disconnected fallback.
/// # C: O(N_entries)
pub fn get_name(parent: &InodeRef, child_ino: Ino) -> Option<String> {
    if parent.file_type() != FileType::Directory { return None; }
    let mut actor = NameOf { want: child_ino, found: None };
    let mut ctx = DirContext::new(0, &mut actor);
    // A backend error aborts the scan; whatever was matched before it stands,
    // since a match is positive evidence and the remaining entries cannot
    // retract it.
    let fop = parent.i_fop().clone();
    let _ = fop.iterate(parent, &mut ctx);
    actor.found
}

/// Reconnect `child` under `parent_dentry` as `name`: the dcache half of
/// Linux's `lookup_one_unlocked` after `exportfs_get_name`.
///
/// Returns the canonical `(parent, name)` dentry, so a later path render and
/// any concurrent walker see ONE dentry for the entry rather than the
/// anonymous alias a plain decode would leave behind. `None` when the cached
/// entry names a different inode — the entry was replaced between the scan and
/// here, which is `ESTALE`.
/// # C: O(1) expected
pub fn reconnect_child(parent_dentry: &Arc<Dentry>, name: &str, child: &InodeRef)
    -> Option<Arc<Dentry>>
{
    let d = crate::dcache::d_add(parent_dentry, name, child.clone());
    match d.inode() {
        Some(i) if i.ino() == child.ino() => Some(d),
        _ => None,
    }
}
