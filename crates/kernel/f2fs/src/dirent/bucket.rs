//! Which block of a directory a name's hash lands in.
//!
//! A directory is a series of LEVELS, each holding twice as many buckets as
//! the last until the widths stop doubling, and each bucket holding two blocks
//! until they start holding four. A name may be in any level up to the
//! directory's current depth, so a lookup that finds nothing at one level goes
//! on to the next rather than concluding the name is absent.
//!
//! The directory's own `i_dir_level` shifts every level's width, which is what
//! lets a directory expected to be large start wide. Ignoring it puts every
//! name in the wrong bucket of the right level — a lookup that misses names
//! that exist, on exactly the directories where it matters.

use crate::uapi::{MAX_DIR_BUCKETS, MAX_DIR_HASH_DEPTH};

/// Buckets in `level` of a directory whose base level is `dir_level`.
/// # C: O(1)
pub fn dir_buckets(level: u32, dir_level: u8) -> u32 {
    let shift = level + u32::from(dir_level);
    if shift < MAX_DIR_HASH_DEPTH / 2 { 1u32 << shift } else { MAX_DIR_BUCKETS }
}

/// Blocks one bucket of `level` holds. # C: O(1)
pub fn bucket_blocks(level: u32) -> u32 {
    if level < MAX_DIR_HASH_DEPTH / 2 { 2 } else { 4 }
}

/// Index of the first block of bucket `idx` in `level`.
///
/// The index is absolute within the directory's data, so it counts every block
/// of every shallower level first.
/// # C: O(level)
pub fn dir_block_index(level: u32, dir_level: u8, idx: u32) -> u64 {
    let mut bidx: u64 = 0;
    for i in 0..level {
        bidx += u64::from(dir_buckets(i, dir_level)) * u64::from(bucket_blocks(i));
    }
    bidx + u64::from(idx) * u64::from(bucket_blocks(level))
}

/// The bucket a hash falls in, at `level`. # C: O(1)
pub fn bucket_of(hash: u32, level: u32, dir_level: u8) -> u32 {
    hash % dir_buckets(level, dir_level)
}

/// The blocks a lookup at `level` must examine for `hash`. # C: O(level)
pub fn search_range(hash: u32, level: u32, dir_level: u8) -> core::ops::Range<u64> {
    let bucket = bucket_of(hash, level, dir_level);
    let start = dir_block_index(level, dir_level, bucket);
    start..start + u64::from(bucket_blocks(level))
}

#[cfg(test)]
#[path = "../tests/bucket.rs"]
mod tests;
