//! Standard timings: eight 2-byte entries naming a size and a refresh rate.
//!
//! The standard stores the horizontal size divided down and the vertical size
//! implied by an aspect-ratio code, so a mode's size is computed rather than
//! stored. No timings accompany them, so the generated mode carries synthesised
//! blanking — the size and refresh rate are what the display actually asserted.

use super::block;
use super::layout::*;
use crate::uapi::{DrmModeModeinfo, DRM_MODE_TYPE_DRIVER};
use alloc::vec::Vec;

/// Size a standard timing entry names, or `None` for an unused entry.
///
/// Unused entries carry one of the standard's three reserved byte pairs. The
/// horizontal size is stored as `(hsize - 248) / 8`; the vertical size follows
/// from the aspect-ratio code, whose zero value means square pixels before
/// revision 3 and 16:10 from revision 3 onward. # C: O(1)
pub fn size_of(byte0: u8, byte1: u8, revision: u8) -> Option<(u32, u32)> {
    if is_unused(byte0, byte1) { return None; }
    let hsize = byte0 as u32 * STD_HSIZE_STEP + STD_HSIZE_BASE;
    let vsize = match (byte1 & STD_ASPECT_MASK) >> STD_ASPECT_SHIFT {
        0 if revision < STD_ASPECT_16_10_FROM_REVISION => hsize,
        0 => hsize * 10 / 16,
        1 => hsize * 3 / 4,
        2 => hsize * 4 / 5,
        _ => hsize * 9 / 16,
    };
    Some((hsize, vsize))
}

/// Byte pairs the standard reserves to mean "no timing here". # C: O(1)
pub fn is_unused(byte0: u8, byte1: u8) -> bool {
    STD_UNUSED_PAIRS.iter().any(|(a, b)| byte0 == *a && byte1 == *b)
}

/// Refresh rate a standard timing entry names, in Hz. # C: O(1)
pub fn refresh_of(byte1: u8) -> u32 {
    (byte1 & STD_VFREQ_MASK) as u32 + STD_VFREQ_BASE
}

/// Mode named by standard timing entry `idx`, or `None` when the slot is
/// unused. # C: O(1)
pub fn mode_at(block: &[u8], idx: usize) -> Option<DrmModeModeinfo> {
    if idx >= STD_TIMING_COUNT { return None; }
    let at = OFF_STANDARD + idx * STD_TIMING_LEN;
    let (byte0, byte1) = (*block.get(at)?, *block.get(at + 1)?);
    let (w, h) = size_of(byte0, byte1, block::revision(block))?;
    if w < MIN_ACTIVE || h < MIN_ACTIVE { return None; }
    let mut m = crate::core_api::mode_from_rect_at(w, h, refresh_of(byte1));
    m.ty = DRM_MODE_TYPE_DRIVER;
    Some(m)
}

/// Every standard timing the block names. # C: O(STD_TIMING_COUNT)
pub fn modes(block: &[u8]) -> Vec<DrmModeModeinfo> {
    (0..STD_TIMING_COUNT).filter_map(|i| mode_at(block, i)).collect()
}
