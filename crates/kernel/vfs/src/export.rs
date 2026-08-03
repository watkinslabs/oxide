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
//   fid       — the FID payload this kernel encodes and its codec, shared by
//               `name_to_handle_at`/`open_by_handle_at` and by fanotify's
//               `FAN_REPORT_FID` info records, which must encode the SAME
//               handle or a fid a watcher was handed cannot be opened.
//   kernfs_fid — the 8-byte node-id handle a kernfs-backed pseudo-filesystem
//               (cgroup2) mints, whose width userspace depends on.
//   reconnect — the upward `get_parent` walk that makes a decoded object reach
//               the filesystem root, plus the acceptable-alias preference.

pub mod fid;
pub mod kernfs_fid;
pub mod reconnect;

pub use kernfs_fid::{HANDLE_TYPE_KERNFS, KERNFS_FID_LEN, decode_kernfs_fid, encode_kernfs_fid};
pub use reconnect::{MAX_RECONNECT_DEPTH, connected_alias, dentry_connected, find_acceptable_alias,
    generic_get_parent, reconnect_path};

use alloc::string::String;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::dirent::DType;
use crate::file_ops::{DirContext, DirEmit};
use crate::inode::{Inode, InodeRef};
use crate::types::{FileType, Ino};

/// Generation value meaning "no incarnation was recorded". A HANDLE encoding it
/// matches any incarnation — the wildcard a decode that never learned a
/// generation needs, and the one the `..`-derived parent of a reconnect walk
/// necessarily uses.
///
/// The rule for an INODE's own generation is the opposite, and deliberately so
/// (see [`generation_matches`]): a superblock-owned inode is always versioned
/// (`SuperBlock::next_inode_generation` never mints this value), so a zero
/// there means the inode has no owning superblock — and an inode with no
/// superblock is unreachable by any handle decode, since decode resolves
/// through `s_op->fh_to_dentry`. It is therefore never a licence to match.
pub const GENERATION_ANY: u32 = 0;

/// Does a handle's encoded generation name this inode's incarnation?
///
/// Only the ENCODED side wildcards. An inode whose own generation is zero is
/// NOT a wildcard: treating it as one would let a handle minted against a
/// versioned incarnation open the unversioned object that later took the
/// number, which is the exact recycle hole the generation exists to close.
/// Mismatch is `ESTALE` at the caller.
/// # C: O(1)
pub fn generation_matches(inode: &Inode, encoded: u32) -> bool {
    encoded == GENERATION_ANY || inode.i_generation() == encoded
}

/// May this superblock mint a handle at all (Linux `exportfs_can_encode_fh`,
/// which is `exportfs_can_decode_fh` for a decodable handle request)?
///
/// A filesystem that cannot turn its own handles back into inodes must report
/// `EOPNOTSUPP` at `name_to_handle_at` rather than hand out a handle whose
/// every later `open_by_handle_at` would be `ESTALE`. In Linux this is the
/// absence of `s_export_op`; here it is [`crate::SuperOps::export_can_decode_fh`].
/// # C: O(1)
pub fn can_encode_fh(sb: &crate::SuperBlock) -> bool { sb.s_op.export_can_decode_fh() }

/// The superblock whose export ops govern a resolved path: the one the path
/// was reached THROUGH, and only then the inode's own back-pointer.
///
/// The reference reaches these ops through the dentry (`dentry->d_sb`), which
/// is always populated because an inode can only exist against a superblock.
/// Here the inode's `i_sb` is a `Weak` the builder has to be told to fill, and
/// only the filesystems with a backing store fill it — every pseudo-filesystem
/// that synthesizes inodes on lookup leaves it empty. Reading the width from
/// the inode therefore silently fell back to the VFS-generic 12-byte handle for
/// exactly the filesystems that override it, so cgroupfs answered every
/// `name_to_handle_at` with EOVERFLOW and the cgroup id was unreadable for
/// every unit, 25 times in one boot, while cgroupfs's own 8-byte encoder sat
/// correct and wired and never consulted.
///
/// Taking the mount's superblock also matches what the caller asked about: the
/// handle is minted for a path, and the path names the mount.
/// # C: O(1)
pub fn export_sb(mount_sb: Option<alloc::sync::Arc<crate::SuperBlock>>,
                 inode_sb: Option<alloc::sync::Arc<crate::SuperBlock>>)
    -> Option<alloc::sync::Arc<crate::SuperBlock>>
{
    mount_sb.or(inode_sb)
}

/// Resolve `ino` on `sb` from the inode cache alone, honoring the encoded
/// generation. The [`crate::SuperOps::fh_to_dentry`] default builds on this;
/// a filesystem with a backing store overrides the hook so an EVICTED inode
/// still resolves (re-read from the store) instead of reporting `ESTALE`.
/// # C: O(log N_ino)
pub fn ilookup_generation(sb: &crate::SuperBlock, ino: Ino, generation: u32) -> Option<InodeRef> {
    // The filesystem ROOT is reachable by definition and is pinned by `s_root`
    // for the mount's whole life, but it is built during fill-super — before
    // the superblock exists — so it never entered the inode cache. Resolving it
    // from `s_root` is what lets the reconnect walk terminate at the top of the
    // tree instead of reporting the root itself stale.
    let inode = sb.ilookup(ino)
        .or_else(|| sb.s_root_inode().filter(|r| r.ino() == ino))?;
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
