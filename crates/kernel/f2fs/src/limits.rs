//! What the format admits, and what this build refuses past.

use crate::uapi;

/// Widest segment count the four-byte block address can reach.
pub const MAX_SEGMENT: u32 = (16 * 1024 * 1024) / 2;
/// Narrowest volume that still has one of each area: the superblock, two
/// checkpoint packs with their SIT and NAT, a summary area and a main area.
pub const MIN_SEGMENTS: u32 = 9;

/// Narrowest and widest `log_sectorsize` the format admits. The upper bound
/// is the block size, because a sector may not exceed the unit it composes.
pub const MIN_LOG_SECTOR_SIZE: u32 = 9;
pub const MAX_LOG_SECTOR_SIZE: u32 = uapi::BLKSIZE_BITS;

/// Longest name, in bytes, and what `statfs` reports.
pub const NAME_MAX: u64 = uapi::NAME_LEN as u64;

/// Deepest hash level a lookup will descend, which bounds the work a
/// corrupted `i_current_depth` can ask for.
pub const MAX_LOOKUP_DEPTH: u32 = uapi::MAX_DIR_HASH_DEPTH;

/// Indirection steps a block index may take, inode included.
pub const MAX_NODE_PATH: usize = 4;

/// Widest read this build will assemble in one call, so a caller asking for a
/// terabyte does not ask for a terabyte of memory first.
pub const MAX_IO_BYTES: usize = 8 * 1024 * 1024;

/// Links a lookup may follow before it declares a loop.
pub const MAX_SYMLINK_BYTES: usize = 4096;

/// The most names one inode may carry. A count at the ceiling refuses another
/// link rather than wrapping — past the maximum a directory reads as one with
/// no parents at all.
pub const F2FS_LINK_MAX: u32 = 0xffff_ffff;
