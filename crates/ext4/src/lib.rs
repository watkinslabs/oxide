// ext4 read-only driver per Linux ext4 disk format.
//
// Phase 6 minimum: superblock parse + inode-table walk + path
// lookup against extent-encoded directories. Write/journaling
// (`docs/17` Phase 7b) ride later.
//
// Hosted-testable: pure on-disk-format parsers take `&[u8]`.
// Block-device I/O lives behind the `BlockDevice` trait that
// callers in the kernel side will plug in (the `block` crate's
// `MemDisk` is enough to hosted-test against synthetic images).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod superblock;
pub use superblock::{Superblock, EXT4_SUPER_MAGIC, SuperblockError};

pub mod inode;
pub use inode::{Inode, InodeError, ExtentHeader, Extent,
                S_IFMT, S_IFREG, S_IFDIR, S_IFLNK,
                EXT4_EXT_MAGIC, parse_extent_header, parse_inline_extent};

pub mod dir;
pub use dir::{DirEntry, DirError, next_entry, iter_active, lookup,
              DT_UNKNOWN, DT_REG, DT_DIR, DT_LNK};
