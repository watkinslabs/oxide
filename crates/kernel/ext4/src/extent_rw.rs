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
// - collect: extent leaf collection for SEEK_HOLE/SEEK_DATA.
// - write: random writes, fallocate, and direct inode size updates.
// - truncate: extent-tree truncation, subtree freeing, and i_blocks accounting.
// - nlink: link-count mutation helper.

mod append;
mod collect;
mod inode_io;
mod insert;
mod nlink;
mod records;
mod truncate;
mod write;

const EXT4_MAX_EXTENT_DEPTH: u16 = 5;

/// Cap per ext4 spec: an extent's `ee_len` is 16 bits, but the
/// top bit signals "uninitialized"; usable max is 0x8000.
pub const EXTENT_LEN_MAX: u16 = 0x8000;

struct ExtentInsertResult {
    first_block: u32,
    split: Option<crate::inode::ExtentIdx>,
    extra_meta_sectors: u32,
}
