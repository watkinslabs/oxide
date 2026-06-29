//! inode-D20 (getattr part): `Kstat.st_blocks` rounds the file size UP to the
//! filesystem allocation unit (`s_blocksize`/`blksize`) before expressing it in
//! 512-byte sectors — so a sub-block file reports a whole block, matching
//! `stat(1)` on ext4/tmpfs. The pre-fix `ceil(size/512)` under-counted every
//! file smaller than (or not a multiple of) one fs block to a single sector.
//! Driven over minimal `Inode` impls through `generic_fillattr`, no QEMU.
//!
//! REMAINS (D20): sparse / preallocated files are still indistinguishable from
//! fully-allocated ones — that needs a real stored per-inode `i_blocks`/`i_bytes`.

use vfs::getattr::blocks_for;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError, IDENTITY};

/// Regular file with an explicit fs block size and logical size.
struct TReg { bs: u32, size: u64 }
impl Inode for TReg {
    fn ino(&self) -> vfs::Ino { 7 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.size }
    fn blksize(&self) -> u32 { self.bs }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn st_blocks(bs: u32, size: u64) -> u64 {
    let f = TReg { bs, size };
    vfs::generic_fillattr(&f, &IDENTITY, None).blocks
}

#[test]
fn sub_block_file_reports_a_whole_block() {
    // 1-byte file on a 4 KiB fs occupies one 4 KiB block = 8 × 512-byte sectors.
    // Pre-fix this was `(1 + 511) / 512 == 1`, under-counting by a factor of 8.
    assert_eq!(st_blocks(4096, 1), 8, "1-byte file on 4 KiB fs == 8 sectors");
    assert_eq!(st_blocks(4096, 100), 8, "any sub-block file rounds up to one block");
}

#[test]
fn empty_file_reports_no_blocks() {
    assert_eq!(st_blocks(4096, 0), 0, "0-byte file occupies no allocation unit");
}

#[test]
fn exact_and_partial_block_multiples_round_up() {
    assert_eq!(st_blocks(4096, 4096), 8,  "exactly one 4 KiB block == 8 sectors");
    assert_eq!(st_blocks(4096, 4097), 16, "one byte into the 2nd block == 16 sectors");
    assert_eq!(st_blocks(4096, 8192), 16, "two full blocks == 16 sectors");
}

#[test]
fn block_size_drives_the_rounding_unit() {
    // 512-byte fs: the unit equals one sector, so it matches ceil(size/512).
    assert_eq!(st_blocks(512, 1), 1, "1-byte file on 512 fs == 1 sector");
    assert_eq!(st_blocks(512, 1000), 2, "ceil(1000/512) == 2 sectors");
    // 1 KiB fs: one block == 2 sectors; a 1-byte file fills one whole 1 KiB block.
    assert_eq!(st_blocks(1024, 1), 2, "1-byte file on 1 KiB fs == 2 sectors");
    assert_eq!(st_blocks(1024, 1025), 4, "1025 bytes == two 1 KiB blocks == 4 sectors");
}

#[test]
fn blocks_for_helper_matches_fillattr() {
    // The exported helper is the single source the stat path uses.
    for &(bs, sz) in &[(4096u32, 1u64), (4096, 0), (4096, 4097), (1024, 1025), (512, 1000)] {
        assert_eq!(blocks_for(sz, bs), st_blocks(bs, sz), "helper == generic_fillattr");
    }
}

#[test]
fn degenerate_block_size_floors_at_one_sector() {
    // A pathological sub-sector block size must never make `blocks` collapse to
    // 0 via a `bs/512 == 0` multiply — the unit floors at one 512-byte sector.
    // Args are (size, bsize).
    assert_eq!(blocks_for(0, 1), 0, "empty file stays 0 regardless of unit");
    assert_eq!(blocks_for(1000, 1), 2, "1-byte unit floored to 512 → ceil(1000/512)");
}
