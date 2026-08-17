//! The thresholds the placement decisions compare against.
//!
//! Each is the value the format's own tuning uses, and each is a threshold a
//! decision READS rather than a preference: changing one changes where blocks
//! land, so they are named here instead of appearing as integers inside the
//! decisions that consult them.

/// Occupancy, as a percentage, above which a mount that armed the utilisation
/// policy rewrites in place.
///
/// The reasoning is the cleaner's: on a nearly-full volume an out-of-place
/// write takes a fresh block and leaves a dead one behind, so the cleaner has
/// to move live blocks to get that space back — while the volume it is
/// cleaning for is the one with no room to move them to.
pub const DEF_MIN_IPU_UTIL: u32 = 70;

/// Dirty pages at or below which an `fsync` asks for its file's writes to land
/// in place.
///
/// A small tail is the case the policy exists for: rewriting eight blocks
/// where they lie costs eight writes, while placing them out of line costs the
/// same eight plus the node blocks naming their new addresses, and the node
/// chain the call then has to write.
pub const DEF_MIN_FSYNC_BLOCKS: u32 = 8;

/// Main-area segments at or below which a volume counts as SMALL, and takes
/// the in-place policy the format tunes small volumes to.
///
/// Sixteen gigabytes' worth. A volume this size cannot afford the free space
/// out-of-place writing needs to stay ahead of the cleaner, so the whole
/// volume is written in place unless something asks otherwise.
pub const SMALL_VOLUME_SEGMENTS: u32 = 16 * 512;

/// A whole share, for the occupancy comparison. # C: O(1)
pub const PERCENT: u32 = 100;
