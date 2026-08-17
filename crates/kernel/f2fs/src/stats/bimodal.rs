//! How far the volume is from the shape a log-structured filesystem wants.
//!
//! A section is cheap to clean when it is empty and free when it is full;
//! the expensive case is half-used, because every live block in it has to be
//! copied to reclaim the dead ones. So the figure that matters is not mean
//! occupancy but how far occupancy is from the middle, squared and summed —
//! high is good, and a volume drifting toward the middle is a volume whose
//! cleaning cost is about to rise.
//!
//! Scaled by what a volume of the same size would score if every section
//! were exactly half full, so the number is comparable between volumes: at
//! or below a hundred is the bad shape, well above it is the good one.

use sectors::SectorSource;

use crate::volume::Volume;

/// The scale the score is reported against. # C: O(1)
const SCALE: u64 = 100;

/// The spread figure, and the mean occupancy of the sections that are neither
/// empty nor full.
///
/// The mean deliberately excludes both extremes: a full section and an empty
/// one are not candidates for cleaning, so averaging them in would report the
/// volume as cheaper or dearer to clean than any actual candidate is.
/// # C: O(main segments)
pub fn of<S: SectorSource>(v: &Volume<S>) -> (u64, u64) {
    let sb = v.super_block();
    let segs_per_sec = sb.segs_per_sec.max(1);
    let main_segs = sb.segment_count_main;
    let blks_per_sec = u64::from(sb.blks_per_seg()) * u64::from(segs_per_sec);
    let half = blks_per_sec / 2;
    let mut spread = 0u64;
    let mut total_vblocks = 0u64;
    let mut ndirty = 0u64;
    let mut nsecs = 0u64;
    let mut segno = 0u32;
    while segno < main_segs {
        let last = (segno + segs_per_sec).min(main_segs);
        let vblocks: u64 = (segno..last).map(|s| u64::from(v.seg_valid(s))).sum();
        let dist = vblocks.abs_diff(half);
        spread += dist * dist;
        if vblocks > 0 && vblocks < blks_per_sec { total_vblocks += vblocks; ndirty += 1; }
        nsecs += 1;
        segno = last;
    }
    let denom = nsecs * half * half / SCALE;
    let bimodal = if denom == 0 { 0 } else { spread / denom };
    let avg = if ndirty == 0 { 0 } else { total_vblocks / ndirty };
    (bimodal, avg)
}
