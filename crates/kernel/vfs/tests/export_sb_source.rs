//! Which superblock supplies a path's export ops.
//!
//! The reference reaches these ops through the dentry (`dentry->d_sb`), which
//! is always populated. Here an inode's `i_sb` is a `Weak` the builder must be
//! told to fill, and only the filesystems with a backing store fill it — every
//! pseudo-filesystem that synthesizes its inodes on lookup leaves it empty.
//!
//! Reading the handle width from the inode therefore fell back to the generic
//! 12-byte FID for exactly the filesystems that override it: cgroupfs's own
//! 8-byte kernfs encoder was correct, wired, and never consulted, so every
//! `name_to_handle_at` on a cgroup answered EOVERFLOW and the cgroup id was
//! unreadable for every unit — 25 of them in one boot.

use std::sync::Arc;

mod common;

use vfs::export::export_sb;
use vfs::fs::FileSystem;
use vfs::superblock::next_anon_dev;
use vfs::{Ino, InodeRef, KResult, SbStatFs, SuperBlock};

/// Stands in for a kernfs-backed pseudo-filesystem: it overrides the handle
/// width to the 8 bytes its callers size their buffers to.
struct NarrowFs;
impl FileSystem for NarrowFs {
    fn name(&self) -> &str { "narrowfs" }
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> { Some(Arc::new(NarrowOps)) }
}

const NARROW_LEN: u32 = 8;

struct NarrowOps;
impl vfs::SuperOps for NarrowOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn export_fid_len(&self, _connectable: bool, _is_dir: bool) -> u32 { NARROW_LEN }
    fn fh_to_dentry(&self, _sb: &SuperBlock, _ino: Ino, _generation: u32) -> Option<InodeRef> {
        None
    }
}

/// A filesystem that does not override the width, so it reports the generic one.
struct WideFs;
impl FileSystem for WideFs {
    fn name(&self) -> &str { "widefs" }
}

fn narrow() -> Arc<SuperBlock> {
    common::realize_sb(Arc::new(NarrowFs), None, next_anon_dev(), String::from("narrowfs"))
}

fn wide() -> Arc<SuperBlock> {
    common::realize_sb(Arc::new(WideFs), None, next_anon_dev(), String::from("widefs"))
}

/// The defect, stated as a test: the inode carries no superblock, and the
/// filesystem's narrower width must still be the one that governs.
#[test]
fn a_path_whose_inode_has_no_superblock_still_uses_the_filesystems_width() {
    let sb = export_sb(Some(narrow()), None).expect("the mount always has one");
    assert_eq!(sb.s_op.export_fid_len(false, true), NARROW_LEN);
}

/// The mount is what the caller named, so it wins over a stale or foreign
/// back-pointer on the inode.
#[test]
fn the_mounts_superblock_is_preferred_over_the_inodes() {
    let generic = wide().s_op.export_fid_len(false, true);
    assert_ne!(generic, NARROW_LEN, "the two fixtures must be distinguishable");
    let sb = export_sb(Some(narrow()), Some(wide())).expect("both present");
    assert_eq!(sb.s_op.export_fid_len(false, true), NARROW_LEN);
}

/// A filesystem whose inode DOES carry its superblock keeps working when the
/// mount cannot be resolved — the back-pointer is the fallback, not dead code.
#[test]
fn the_inodes_superblock_is_the_fallback_when_the_mount_is_gone() {
    let sb = export_sb(None, Some(narrow())).expect("inode back-pointer");
    assert_eq!(sb.s_op.export_fid_len(false, true), NARROW_LEN);
}

/// Neither source: the caller must see no superblock rather than a synthesized
/// one, so it can report the error instead of minting a handle nothing decodes.
#[test]
fn no_superblock_at_all_stays_none() {
    assert!(export_sb(None, None).is_none());
}
