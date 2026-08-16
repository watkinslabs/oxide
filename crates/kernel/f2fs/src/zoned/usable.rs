//! How much of a segment and a section may actually be written.
//!
//! A section maps onto a zone, and a zone whose capacity is shorter than its
//! length leaves a tail of blocks that exist in the address space and can
//! never hold data. The tail is at the END of the section, so the segments
//! before it are whole, one segment straddles the capacity and is short, and
//! the segments after it are entirely unusable.
//!
//! Getting this wrong is not a space-accounting slip. A segment believed
//! whole that is not places blocks past the zone's capacity, where the drive
//! refuses the write; a section believed short that is not strands space
//! nothing ever reclaims.

use crate::sb::SuperBlock;

use super::geom::Geometry;

/// Blocks a section holds, ignoring capacity. # C: O(1)
pub fn blks_per_sec(sb: &SuperBlock) -> u32 {
    sb.segs_per_sec.saturating_mul(sb.blks_per_seg())
}

/// Blocks a section may hold. # C: O(1)
pub fn cap_blks_per_sec(sb: &SuperBlock, geom: Option<&Geometry>) -> u32 {
    blks_per_sec(sb).saturating_sub(unusable(geom))
}

/// Segments a section may hold. # C: O(1)
pub fn cap_segs_per_sec(sb: &SuperBlock, geom: Option<&Geometry>) -> u32 {
    sb.segs_per_sec.saturating_sub(unusable(geom) >> sb.log_blocks_per_seg)
}

/// Blocks segment `segno` may hold.
///
/// `segno` is a main-area segment number. The three cases are the three
/// positions a segment can take relative to its section's capacity: wholly
/// inside it, straddling it, or wholly past it.
/// # C: O(1)
pub fn usable_blks_in_seg(sb: &SuperBlock, geom: Option<&Geometry>, segno: u32) -> u32 {
    let per_seg = sb.blks_per_seg();
    if unusable(geom) == 0 { return per_seg; }
    let secno = segno / sb.segs_per_sec.max(1);
    let sec_first_seg = secno.saturating_mul(sb.segs_per_sec);
    let seg_start = u64::from(segno) * u64::from(per_seg);
    let sec_start = u64::from(sec_first_seg) * u64::from(per_seg);
    let sec_cap = sec_start + u64::from(cap_blks_per_sec(sb, geom));
    if seg_start >= sec_cap { return 0; }
    if seg_start + u64::from(per_seg) > sec_cap { return (sec_cap - seg_start) as u32; }
    per_seg
}

/// Segments of a section that may hold blocks. # C: O(1)
pub fn usable_segs_in_sec(sb: &SuperBlock, geom: Option<&Geometry>) -> u32 {
    if unusable(geom) == 0 { return sb.segs_per_sec; }
    cap_segs_per_sec(sb, geom)
}

/// The one figure every answer above turns on. A volume with no geometry, or
/// one whose zones are all full-capacity, has none. # C: O(1)
fn unusable(geom: Option<&Geometry>) -> u32 {
    geom.map_or(0, |g| g.unusable_blocks_per_sec)
}
