//! How old a block is, and how that age is carried forward.
//!
//! Age is measured in BLOCKS ALLOCATED VOLUME-WIDE, not in seconds. A wall
//! clock says how long a file sat on a quiet volume; the allocation count says
//! how much writing happened around it, which is the thing that decides
//! whether keeping it beside other data was a good guess. A volume that was
//! powered off for a month has aged nothing.
//!
//! An age is not replaced, it DECAYS. The new interval and the old age are
//! blended by a fixed weight, so one out-of-pattern rewrite cannot make a cold
//! block look hot and one quiet spell cannot make a hot block look cold.

use super::limits::{LAST_AGE_WEIGHT, PERCENT};

/// Blend a freshly measured interval with the age already recorded.
///
/// The arithmetic is done on the quotient and the remainder separately so it
/// stays exact in integers: scaling first would overflow on a volume that has
/// allocated a large number of blocks, and dividing first would throw away the
/// low two digits of every age.
/// # C: O(1)
pub fn calculate_block_age(new: u64, old: u64, weight: u32) -> u64 {
    let w = u64::from(weight.min(PERCENT));
    let hundred = u64::from(PERCENT);
    let (q_new, r_new) = (new / hundred, new % hundred);
    let (q_old, r_old) = (old / hundred, old % hundred);
    let mut res = q_new * (hundred - w) + q_old * w;
    if r_new != 0 { res += r_new * (hundred - w) / hundred; }
    if r_old != 0 { res += r_old * w / hundred; }
    res
}

/// The default share the previous age keeps. # C: O(1)
pub const fn default_weight() -> u32 { LAST_AGE_WEIGHT }

/// How long ago a block was written, given what the volume has allocated
/// since it was last measured.
///
/// The allocation count is unsigned and monotonic until it wraps; the wrapped
/// case is handled rather than clamped, because clamping would report a block
/// written a moment ago as the oldest on the volume.
/// # C: O(1)
pub fn interval(cur_blocks: u64, last_blocks: u64) -> u64 {
    if cur_blocks >= last_blocks { cur_blocks - last_blocks }
    else { (u64::MAX - 1) - last_blocks + cur_blocks }
}

/// Whether a block's age must NOT be recorded because the write that produced
/// it says nothing about age.
///
/// The last block of a file whose size does not fill it is rewritten by every
/// append, however sequential the writing is. Recording that as a fresh age
/// would make the tail of every growing file look like the hottest data on the
/// volume.
/// # C: O(1)
pub fn is_unaged_tail(i_size: u64, fofs: u32, block_bits: u32, newly_allocated: bool) -> bool {
    let partial = i_size & ((1u64 << block_bits) - 1) != 0;
    newly_allocated && partial && (i_size >> block_bits) == u64::from(fofs)
}

#[cfg(test)]
#[path = "../tests/extcache/age.rs"]
mod tests;
