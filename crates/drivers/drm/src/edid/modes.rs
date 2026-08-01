//! Every mode an EDID base block publishes, in the order the standard ranks
//! them: detailed timings first (the display's own, most exact), then the
//! established set, then the standard timings.
//!
//! Nothing here filters by what a particular scanout can drive — that is the
//! consumer's decision. This owner reports what the display said.

use super::{block, dtd, established, standard};
use crate::uapi::{DrmModeModeinfo, DRM_MODE_TYPE_PREFERRED};
use alloc::vec::Vec;

/// Two modes are the same offer when they name the same size at the same rate.
/// # C: O(1)
fn same_offer(a: &DrmModeModeinfo, b: &DrmModeModeinfo) -> bool {
    a.hdisplay == b.hdisplay && a.vdisplay == b.vdisplay && a.vrefresh == b.vrefresh
}

/// Append `m` unless an equal offer is already present. Earlier entries win,
/// so a detailed timing is never displaced by a synthesised one for the same
/// size and rate. # C: O(out)
fn push_unique(out: &mut Vec<DrmModeModeinfo>, m: DrmModeModeinfo) {
    if out.iter().any(|have| same_offer(have, &m)) { return; }
    out.push(m);
}

/// Every detailed timing the base block carries, preferred one first when the
/// block marks it so. # C: O(DTD_COUNT)
pub fn detailed(block_bytes: &[u8]) -> Vec<DrmModeModeinfo> {
    let mut out = Vec::new();
    let mut preferred = block::first_detailed_is_preferred(block_bytes);
    for i in 0..super::layout::DTD_COUNT {
        let Some(d) = block::descriptor(block_bytes, i) else { continue };
        let Some(t) = dtd::decode(d) else { continue };
        let mut m = t.to_mode();
        if preferred { m.ty |= DRM_MODE_TYPE_PREFERRED; preferred = false; }
        push_unique(&mut out, m);
    }
    out
}

/// Every mode the blob publishes, or an empty list when it is not a valid base
/// block. Duplicates are collapsed by size and refresh rate.
/// # C: O(modes squared)
pub fn all(bytes: &[u8]) -> Vec<DrmModeModeinfo> {
    let Some(b) = block::base_block(bytes) else { return Vec::new() };
    if !block::is_valid(b) { return Vec::new() }
    let mut out = detailed(b);
    for m in established::modes(b) { push_unique(&mut out, m); }
    for m in standard::modes(b) { push_unique(&mut out, m); }
    out
}
