//! What the cache will hold, and the arithmetic that decides when it is full.
//!
//! Every number here bounds a structure that grows with use. A cache with no
//! ceiling is a memory leak that only shows on a volume large enough to fill
//! it, which is the volume nobody tests on.

use core::mem::size_of;

use crate::uapi::NAT_ENTRY_PER_BLOCK;

use super::state::NidState;

/// Table blocks one build pass walks before it stops and hands back what it
/// found. A pass that read the whole table would make the first allocation on
/// a large volume pay for every id it will never use.
pub const FREE_NID_PAGES: u32 = 8;

/// Ids the cache keeps before a shrink is worth running. The bound is stated
/// in table blocks rather than in ids so it scales with the block size.
pub const MAX_FREE_NIDS: u32 = NAT_ENTRY_PER_BLOCK as u32 * FREE_NID_PAGES;

/// Ids one shrink pass drops before it re-tests its own condition. Dropping
/// the whole excess in one sweep holds the state for as long as that takes;
/// the batch is what keeps a shrink interruptible.
pub const SHRINK_NID_BATCH_SIZE: u32 = 8;

/// The share of memory the cache may occupy, in percent, as a mount starts.
/// Writable: a volume with room to spare can afford to remember more ids than
/// one that is already short.
pub const DEF_RAM_THRESHOLD: u32 = 1;

/// The denominator `ram_thresh` is a numerator over.
pub const RAM_THRESH_BASE: u64 = 100;

/// The share of the threshold this cache in particular may take — a quarter,
/// as a shift, because the other consumers of the same threshold divide it
/// between them the same way.
pub const FREE_NID_SHARE_SHIFT: u32 = 2;

/// Bytes to a page, as a shift. The footprint is measured in bytes and the
/// budget is stated in pages, and this is the only place the two units meet.
pub const MEM_PAGE_SHIFT: u32 = 12;

/// Bytes one remembered id costs: the key it is found by, the state beside
/// it, and its place in the order free ones are handed out in.
pub const ENTRY_BYTES: usize =
    size_of::<u32>() + size_of::<NidState>() + size_of::<u64>() + size_of::<u32>();

/// Bits, and therefore ids, one table block's free map covers.
pub const BITS_PER_NAT_BLOCK: usize = NAT_ENTRY_PER_BLOCK;

/// Bytes that map takes.
pub const NAT_BLOCK_MAP_BYTES: usize = BITS_PER_NAT_BLOCK.div_ceil(8);
