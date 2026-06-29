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

use vfs::inode::Inode;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{FileType, InodeRef, KResult, VfsError, IDENTITY};

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

/// Inode attached to a SuperBlock, advertising a DIFFERENT per-inode
/// `blksize()` (512) than its SB's `s_blocksize` — proves the SB wins.
struct SbInode { sb: Arc<SuperBlock>, size: u64 }
impl Inode for SbInode {
    fn ino(&self) -> vfs::Ino { 5 }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { Some(self.sb.clone()) }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.size }
    fn blksize(&self) -> u32 { 512 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// SB-less anon inode: `i_sb()` defaults `None`, so `blksize()` is the source.
struct AnonInode;
impl Inode for AnonInode {
    fn ino(&self) -> vfs::Ino { 6 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 1 }
    fn blksize(&self) -> u32 { 1024 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

// st_blksize comes from the SB (2048), NOT the inode's own blksize() (512).
#[test]
fn blksize_from_superblock_not_inode() {
    let i = SbInode { sb: sb(2048), size: 1 };
    let st = vfs::generic_fillattr(&i, &IDENTITY, None);
    assert_eq!(st.blksize, 2048, "st_blksize == s_blocksize, not the per-inode 512");
    // st_blocks rounds a 1-byte file UP to one whole 2 KiB block = 4 sectors.
    assert_eq!(st.blocks, 2048 / 512, "one 2 KiB block in 512-byte sectors");
}

// A larger fs blocksize flows through to both fields identically.
#[test]
fn blksize_tracks_sb_value() {
    let st = vfs::generic_fillattr(&SbInode { sb: sb(4096), size: 1 }, &IDENTITY, None);
    assert_eq!(st.blksize, 4096);
    assert_eq!(st.blocks, 4096 / 512);
}

// No SB -> the per-inode blksize() fallback is used (Linux anon inodes).
#[test]
fn sbless_inode_falls_back_to_inode_blksize() {
    let st = vfs::generic_fillattr(&AnonInode, &IDENTITY, None);
    assert_eq!(st.blksize, 1024, "no i_sb() -> per-inode blksize() fallback");
}
