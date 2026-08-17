//! The numbers the extent caches are bounded by.
//!
//! Every one of these is part of the observable contract rather than a taste:
//! the minimum length decides which fragments the read cache refuses to keep,
//! the same-age region decides which neighbouring runs the age cache calls one
//! run, and the two thresholds decide what a block's age makes it. A build
//! that picked its own would answer differently for the same volume.

/// Shortest run the READ cache will keep as an entry of its own.
///
/// A cache full of one-block entries costs more to walk than the node tree it
/// replaces, so a split that would leave a shorter fragment drops it instead.
pub const F2FS_MIN_EXTENT_LEN: u32 = 64;

/// Entries one shrink pass of the read cache tries to free.
pub const READ_EXTENT_CACHE_SHRINK_NUMBER: usize = 128;

/// Entries one shrink pass of the age cache tries to free.
pub const AGE_EXTENT_CACHE_SHRINK_NUMBER: usize = 128;

/// Weight, in percent, the PREVIOUS age keeps when a block's age is renewed.
///
/// The remaining share goes to the age just measured, so a block's recorded
/// age is a decayed average rather than its last interval alone — one
/// out-of-pattern rewrite must not make a cold block look hot.
pub const LAST_AGE_WEIGHT: u32 = 30;

/// How far two neighbouring runs' ages may differ and still be called one run.
pub const SAME_AGE_REGION: u64 = 1024;

/// Age below which a data block is hot, measured in blocks allocated
/// volume-wide since the block was written.
pub const DEF_HOT_DATA_AGE_THRESHOLD: u32 = 262_144;

/// Age below which a data block is warm rather than cold.
pub const DEF_WARM_DATA_AGE_THRESHOLD: u32 = 2_621_440;

/// Entries the READ cache keeps for one inode before it stops splitting.
pub const DEF_MAX_READ_EXTENT_COUNT: u32 = 10_240;

/// The `last_blocks` value that marks an age update as carrying no age at all.
///
/// A range update that only invalidates — a truncate, a hole punch — says so
/// with this rather than with a separate call, so the invalidate half of the
/// algorithm is one path for both caches.
pub const F2FS_EXTENT_AGE_INVALID: u64 = u64::MAX;

/// Percent, as the denominator the age weighting is expressed in.
pub const PERCENT: u32 = 100;
