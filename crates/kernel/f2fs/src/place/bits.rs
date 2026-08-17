//! Which in-place-update policies a mount can have armed.
//!
//! A SET rather than a choice: several can be armed at once and each asks a
//! different question, so the word is read bit by bit and the first bit that
//! says yes decides. The positions are the report's ABI — a reader decodes the
//! set by name and the names are listed in this order — which is why they are
//! named constants here rather than shifts written at the sites that test them.

/// Rewrite in place always.
pub const FORCE: u32 = 0;
/// Rewrite in place while the allocator is reusing partly-used segments.
pub const SSR: u32 = 1;
/// Rewrite in place once the volume is fuller than the utilisation threshold.
pub const UTIL: u32 = 2;
/// Both of the two above, together.
pub const SSR_UTIL: u32 = 3;
/// Rewrite in place for the writes an `fsync` asks for, and no others.
pub const FSYNC: u32 = 4;
/// Rewrite in place for writes nothing is waiting on.
pub const ASYNC: u32 = 5;
/// Submit an in-place write on its own rather than merging it with the batch
/// around it.
pub const NOCACHE: u32 = 6;
/// Let a file that has asked for out-of-place writes have them, whatever else
/// is armed.
pub const HONOR_OPU_WRITE: u32 = 7;
/// One past the highest position the word uses.
pub const MAX: u32 = 8;

/// The whole word cleared: no policy armed, so every write is out of place.
pub const DISABLE: u32 = 0;

/// The names, indexed by bit position.
pub const NAMES: [&str; MAX as usize] =
    ["FORCE", "SSR", "UTIL", "SSR_UTIL", "FSYNC", "ASYNC", "NOCACHE", "HONOR_OPU_WRITE"];

/// The word with `pos` raised. # C: O(1)
pub const fn bit(pos: u32) -> u32 { 1u32 << pos }

/// Whether `policy` has `pos` armed. # C: O(1)
pub const fn armed(policy: u32, pos: u32) -> bool { policy & bit(pos) != 0 }
