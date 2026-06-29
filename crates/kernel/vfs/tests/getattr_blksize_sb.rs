//! inode-D40: `st_blksize` is a SUPERBLOCK property (Linux `s_blocksize`), not a
//! per-inode one. `generic_fillattr` routes the blocksize through the owning
//! `i_sb().s_blocksize`, falling back to the per-inode `Inode::blksize()` ONLY
//! for an SB-less anon inode (pidfd/pipe/socket). The same effective allocation
//! unit also drives `st_blocks` (`blocks_for`), so a one-byte file on a 2 KiB-
//! block fs reports a whole 2 KiB block regardless of any per-inode `blksize()`.
//!
//! Fails-before: a `generic_fillattr` that read `inode.blksize()` directly would
//! report the wrong `st_blksize` (and `st_blocks`) for every inode on a fs whose
//! `s_blocksize` differs from the 4096 trait default — e.g. a 1 KiB/2 KiB ext4.
//! This pins the SB override.
//!
//! Builds a real `SuperBlock` with a non-default blocksize; no global state
//! mutated, no serial guard.

use std::sync::Arc;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{FileType, InodeBuilder, InodeRef, KResult, IDENTITY,
          default_file_ops, default_inode_ops, mk_mode};

struct NullType;
impl FileSystemType for NullType {
    fn name(&self) -> &str { "t" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { unreachable!() }
}
struct NullOps;
impl SuperOps for NullOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn sb(blocksize: u32) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(NullType), Arc::new(NullOps), 0, 0x10, blocksize, "t".into(), Arc::new(()))
}

/// Inode attached to a SuperBlock; `st_blksize` derives from its `s_blocksize`.
fn sb_inode(sb: &Arc<SuperBlock>, size: u64) -> InodeRef {
    InodeBuilder::new(5, mk_mode(FileType::Regular, 0), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).size(size).build()
}

/// SB-less anon inode: `i_sb()` is `None`, so `blksize()` falls back to the
/// generic 4096 default (the concrete-inode model dropped the per-inode
/// `blksize()` override that used to source this).
fn anon_inode() -> InodeRef {
    InodeBuilder::new(6, mk_mode(FileType::Regular, 0), default_inode_ops(), default_file_ops())
        .size(1).build()
}

// st_blksize comes from the SB (2048), not the generic 4096 default.
#[test]
fn blksize_from_superblock_not_inode() {
    let s = sb(2048);
    let st = vfs::generic_fillattr(&sb_inode(&s, 1), &IDENTITY, None);
    assert_eq!(st.blksize, 2048, "st_blksize == s_blocksize, not the 4096 default");
    // st_blocks rounds a 1-byte file UP to one whole 2 KiB block = 4 sectors.
    assert_eq!(st.blocks, 2048 / 512, "one 2 KiB block in 512-byte sectors");
}

// A larger fs blocksize flows through to both fields identically.
#[test]
fn blksize_tracks_sb_value() {
    let s = sb(4096);
    let st = vfs::generic_fillattr(&sb_inode(&s, 1), &IDENTITY, None);
    assert_eq!(st.blksize, 4096);
    assert_eq!(st.blocks, 4096 / 512);
}

// No SB -> the generic 4096 fallback (Linux anon inodes; the per-inode
// blksize() override no longer exists in the concrete-inode model).
#[test]
fn sbless_inode_falls_back_to_inode_blksize() {
    let st = vfs::generic_fillattr(&anon_inode(), &IDENTITY, None);
    assert_eq!(st.blksize, 4096, "no i_sb() -> generic 4096 blksize() fallback");
}
