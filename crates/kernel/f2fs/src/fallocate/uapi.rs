//! The mode bits, which are the ABI a caller passes in.

/// Give the file blocks without changing what it says its length is.
pub const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
/// Take the blocks of a range away, leaving a hole of the same length.
pub const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
/// Take a range out and close the gap, shortening the file.
pub const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
/// Make a range read as zeroes, allocating where it was a hole.
pub const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
/// Open a gap at a point, moving everything after it along.
pub const FALLOC_FL_INSERT_RANGE: u32 = 0x20;

/// Every bit this filesystem acts on. A mode carrying anything else is refused
/// rather than masked: a caller that asked for a bit nobody honoured would be
/// told its request succeeded and get something else.
pub const FALLOC_FL_SUPPORTED: u32 = FALLOC_FL_KEEP_SIZE
    | FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_COLLAPSE_RANGE
    | FALLOC_FL_ZERO_RANGE
    | FALLOC_FL_INSERT_RANGE;

/// The four that take blocks away from, or move blocks within, a file that
/// already has them.
///
/// Grouped because they share one refusal: a file whose blocks something
/// outside the filesystem is addressing, or whose blocks are a compressed
/// image rather than an index, cannot have any of them done to it.
pub const FALLOC_FL_PARTIAL: u32 = FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_COLLAPSE_RANGE
    | FALLOC_FL_ZERO_RANGE
    | FALLOC_FL_INSERT_RANGE;

/// The two that change which index each block answers to.
pub const FALLOC_FL_MOVES: u32 = FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE;
