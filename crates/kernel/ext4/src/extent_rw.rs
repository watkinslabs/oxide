// File-data RW path: append, sparse allocation, write, and truncate.
// Allocation inserts extents in logical-block order, grows adjacent physical
// runs when possible, and splits inline/external extent nodes instead of
// relying on append-only metadata layout.
//
// Module manifest:
// - append: public append entry points and top-level logical block insertion.
// - insert: recursive extent-tree insertion and inline-root growth.
// - records: extent/index vector parsing, writing, sorting, splitting helpers.
// - inode_io: raw inode byte I/O, extent-block writes, and block-group helpers.
// - meta: on-disk mode/owner/timestamp writeback (the ext4 half of setattr).
// - collect: extent leaf collection for SEEK_HOLE/SEEK_DATA.
// - write: random writes, fallocate, and direct inode size updates.
// - limits: bounded writeback-cluster sizing shared with the frame cache.
// - truncate: extent-tree truncation, subtree freeing, and i_blocks accounting.
// - nlink: link-count mutation helper.

mod append;
mod collect;
mod inode_io;
pub(crate) mod meta;
mod insert;
mod nlink;
mod punch;
mod records;
mod truncate;
mod write;
mod limits;

pub(crate) use limits::DATA_WRITE_CLUSTER_BYTES;

pub(crate) use crate::inode::EXT4_MAX_EXTENT_DEPTH;

/// Cap per ext4 spec: an extent's `ee_len` is 16 bits, but the
/// top bit signals "uninitialized"; usable max is 0x8000.
pub const EXTENT_LEN_MAX: u16 = 0x8000;

struct ExtentInsertResult {
    first_block: u32,
    split: Option<crate::inode::ExtentIdx>,
    extra_meta_sectors: u32,
    allocated_meta_blocks: alloc::vec::Vec<u64>,
}

/// External xattr blocks are inode-owned storage and therefore contribute one
/// filesystem block to `i_blocks`. Extent-tree rebuilds must preserve that
/// charge instead of replacing `i_blocks` with the extent-only total.
pub(super) fn external_xattr_sectors(sb: &crate::Superblock, inode: &[u8]) -> u32 {
    if inode.len() < 0x78 { return 0; }
    let lo = u32::from_le_bytes([inode[0x68], inode[0x69], inode[0x6a], inode[0x6b]]);
    let hi = u16::from_le_bytes([inode[0x76], inode[0x77]]);
    if lo == 0 && hi == 0 { 0 } else { sb.block_size / 512 }
}
