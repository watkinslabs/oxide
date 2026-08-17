//! Directory entries: the four parallel arrays one block holds, and where in
//! a directory a name's block is.
//!
//! A dentry region is not a list of records. It is a validity BITMAP, a
//! padding gap, an array of fixed eleven-byte records, and an array of
//! eight-byte name slots — four regions whose sizes are all derived from one
//! entry count. A name longer than eight bytes spans consecutive slots, and
//! the records for those extra slots are skipped rather than read, so a walker
//! that advances one record at a time reads the middle of a name as a record.
//!
//! Two regions have this shape with different sizes: a whole block, and the
//! inline region inside an inode. Everything below takes the layout as a
//! parameter so the two cannot drift apart.
//!
//! Module manifest:
//! - `layout`: the four regions' sizes, for a block and for an inline region.
//! - `block`:  reading entries out of a region.
//! - `bucket`: which block of a directory a hash lands in.

pub mod layout;
pub mod block;
pub mod bucket;

pub use block::{entries, find, Entry};
pub use bucket::{bucket_blocks, dir_block_index, dir_buckets};
pub use layout::Layout;

use crate::flags::*;

/// The VFS-facing kind of an entry's stored type byte. # C: O(1)
pub fn is_dir(file_type: u8) -> bool { file_type == FT_DIR }

/// Whether a stored type byte is one the format defines. # C: O(1)
pub fn known_type(file_type: u8) -> bool { file_type < FT_MAX }
