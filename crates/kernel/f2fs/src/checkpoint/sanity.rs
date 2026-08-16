//! Whether a checkpoint's layout figures describe a volume that can be run.
//!
//! These are not integrity checks — the CRC and the two packs' versions have
//! already answered that. They are checks that the numbers a FORMATTER wrote
//! add up, and a volume whose numbers do not is refused rather than mounted
//! with a floor substituted for the missing value.
//!
//! The reserve is the one that matters most. Segments held back from the
//! allocator are the only place the cleaner has to move live blocks TO, so a
//! volume formatted with none has a cleaner that cannot run at the one moment
//! it is wanted — when the volume is full. Substituting a floor of one hides
//! that: the mount succeeds, the report says the volume reserves a segment it
//! does not, and the first full-volume clean fails with nowhere to go. A
//! volume whose features permit only reads is exempt, because it never
//! allocates and never cleans, and its formatter writes no reserve.

use crate::checkpoint::Checkpoint;
use crate::sb::SuperBlock;

/// Why a checkpoint's layout figures were refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LayoutError {
    /// The metadata areas and the reserve claim the whole volume or more.
    MetaTooLarge,
    /// Less metadata than the smallest layout the format defines.
    MetaTooSmall,
    /// No segments held back for over-provisioning.
    NoOverprovision,
    /// No segments held back for the cleaner to move live blocks into.
    NoReserve,
}

/// Segments the smallest layout the format defines occupies: the superblock,
/// two each of the checkpoint, segment-table and node-table areas, and the
/// summary area.
pub const MIN_META_SEGMENTS: u32 = 8;

/// Whether `cp`'s figures and `sb`'s areas describe a runnable volume.
/// # C: O(1)
pub fn check(cp: &Checkpoint, sb: &SuperBlock) -> Result<(), LayoutError> {
    let meta = sb.segment_count_ckpt
        .saturating_add(sb.segment_count_sit)
        .saturating_add(sb.segment_count_nat)
        .saturating_add(cp.rsvd_segment_count)
        .saturating_add(sb.segment_count_ssa);
    if meta >= sb.segment_count { return Err(LayoutError::MetaTooLarge); }
    // A volume the format marks read-only was written by something that laid
    // down only what a reader needs: no over-provisioning and no reserve,
    // because it will never allocate.
    if sb.feature & crate::flags::FEATURE_RO != 0 { return Ok(()); }
    if meta < MIN_META_SEGMENTS { return Err(LayoutError::MetaTooSmall); }
    if cp.overprov_segment_count == 0 { return Err(LayoutError::NoOverprovision); }
    if cp.rsvd_segment_count == 0 { return Err(LayoutError::NoReserve); }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/checkpoint/sanity.rs"]
mod tests;
