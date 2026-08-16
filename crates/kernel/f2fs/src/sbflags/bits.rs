//! Bit positions of the volume-wide status word.
//!
//! The positions are the ABI: a reader decodes the word by bit number, so they
//! are named rather than written into a shift, and their order is the order the
//! contract fixes rather than the order this build happened to implement them
//! in.

/// Something is waiting for a checkpoint.
pub const IS_DIRTY: u32 = 0;
/// The volume is being unmounted, or flushed as if it were.
pub const IS_CLOSE: u32 = 1;
/// The volume needs `fsck`.
pub const NEED_FSCK: u32 = 2;
/// A recovery replay is in progress.
pub const POR_DOING: u32 = 3;
/// A superblock write is owed: one was needed while the medium refused writes.
pub const NEED_SB_WRITE: u32 = 4;
/// A checkpoint is owed before any `fsync` may take the node-chain path.
pub const NEED_CP: u32 = 5;
/// The volume was shut down by ioctl and accepts no further writes.
pub const IS_SHUTDOWN: u32 = 6;
/// This mount replayed orphans or a node chain.
pub const IS_RECOVERED: u32 = 7;
/// Checkpointing is off for this mount.
pub const CP_DISABLED: u32 = 8;
/// Checkpointing was turned off on the short timer rather than the long one.
pub const CP_DISABLED_QUICK: u32 = 9;
/// Quota records changed and the next checkpoint must flush them.
pub const QUOTA_NEED_FLUSH: u32 = 10;
/// The current checkpoint gives up on flushing quota records.
pub const QUOTA_SKIP_FLUSH: u32 = 11;
/// A quota file may be inconsistent and needs repair.
pub const QUOTA_NEED_REPAIR: u32 = 12;
/// A resize is part-way through.
pub const IS_RESIZEFS: u32 = 13;
/// A freeze is part-way through.
pub const IS_FREEZING: u32 = 14;
/// A read-only mount is writing anyway, for the length of a repair.
pub const IS_WRITABLE: u32 = 15;
/// Checkpointing is being turned back on.
pub const ENABLE_CHECKPOINT: u32 = 16;

/// One past the highest position the word uses.
pub const MAX_SBI_FLAG: u32 = 17;

/// The word with `pos` raised. # C: O(1)
pub const fn bit(pos: u32) -> u64 { 1u64 << pos }

/// The positions that are NOT stored in the flag word.
///
/// Both are the volume's own state already — the dirty mark a write leaves and
/// the replay a mount runs — and storing a second copy would let the two
/// disagree, which is the failure this mask exists to prevent.
pub const DERIVED: u64 = bit(IS_DIRTY) | bit(POR_DOING);

/// Whether `pos` names a condition the flag word stores. # C: O(1)
pub const fn stored(pos: u32) -> bool { bit(pos) & DERIVED == 0 }
