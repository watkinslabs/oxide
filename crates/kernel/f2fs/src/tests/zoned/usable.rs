//! How much of a segment and a section may be written.

use alloc::vec::Vec;

use crate::flags::FEATURE_BLKZONED;
use crate::sb::SuperBlock;
use crate::test_image as image;
use crate::uapi::{SUPER_OFFSET, SUPER_SIZE};
use crate::zoned::usable::{
    blks_per_sec, cap_blks_per_sec, cap_segs_per_sec, usable_blks_in_seg, usable_segs_in_sec,
};
use crate::zoned::{DevZones, Geometry, Zone, ZoneType};

/// A fixture superblock whose sections hold `segs_per_sec` segments.
fn sb() -> SuperBlock {
    let bytes = image::Builder::new().finish();
    crate::sb::parse(&bytes[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE]).expect("parses")
}

/// A geometry whose sections lose `unusable` blocks at the end.
fn geom(sb: &SuperBlock, unusable: u32) -> Geometry {
    let per_sec = blks_per_sec(sb);
    let zones: Vec<Zone> = (0..4u64)
        .map(|i| Zone::fresh(i * u64::from(per_sec), per_sec, per_sec - unusable,
                             ZoneType::SeqWriteRequired))
        .collect();
    let r = DevZones { blocks_per_zone: per_sec, max_open_zones: None, zones };
    Geometry::build(FEATURE_BLKZONED, &[Some(r)], 6).expect("builds")
}

#[test]
fn without_a_geometry_every_segment_is_whole() {
    let s = sb();
    for segno in 0..4 {
        assert_eq!(usable_blks_in_seg(&s, None, segno), s.blks_per_seg());
    }
    assert_eq!(usable_segs_in_sec(&s, None), s.segs_per_sec);
    assert_eq!(cap_blks_per_sec(&s, None), blks_per_sec(&s));
}

#[test]
fn a_full_capacity_geometry_is_the_same_as_none() {
    let s = sb();
    let g = geom(&s, 0);
    for segno in 0..4 {
        assert_eq!(usable_blks_in_seg(&s, Some(&g), segno), s.blks_per_seg());
    }
    assert_eq!(cap_blks_per_sec(&s, Some(&g)), blks_per_sec(&s));
    assert_eq!(usable_segs_in_sec(&s, Some(&g)), s.segs_per_sec);
}

#[test]
fn a_section_loses_exactly_the_unusable_blocks() {
    let s = sb();
    let g = geom(&s, 8);
    assert_eq!(cap_blks_per_sec(&s, Some(&g)), blks_per_sec(&s) - 8);
}

#[test]
fn a_segment_straddling_the_capacity_is_short_by_the_overhang() {
    // The fixture's section is one segment, so segment zero itself straddles.
    let s = sb();
    let g = geom(&s, 8);
    assert_eq!(usable_blks_in_seg(&s, Some(&g), 0), s.blks_per_seg() - 8);
    assert_eq!(usable_blks_in_seg(&s, Some(&g), 3), s.blks_per_seg() - 8);
}

#[test]
fn a_segment_wholly_past_the_capacity_holds_nothing() {
    // A section that loses a whole segment's worth: the last segment of each
    // section starts at or past the capacity and can hold no block at all.
    let s = sb();
    let per_seg = s.blks_per_seg();
    let mut s2 = s.clone();
    s2.segs_per_sec = 2;
    let g = geom(&s2, per_seg);
    assert_eq!(usable_blks_in_seg(&s2, Some(&g), 0), per_seg);
    assert_eq!(usable_blks_in_seg(&s2, Some(&g), 1), 0);
    assert_eq!(usable_blks_in_seg(&s2, Some(&g), 2), per_seg);
    assert_eq!(usable_blks_in_seg(&s2, Some(&g), 3), 0);
}

#[test]
fn a_whole_lost_segment_is_lost_from_the_section_count_too() {
    let s = sb();
    let per_seg = s.blks_per_seg();
    let mut s2 = s.clone();
    s2.segs_per_sec = 2;
    let g = geom(&s2, per_seg);
    assert_eq!(cap_segs_per_sec(&s2, Some(&g)), 1);
    assert_eq!(usable_segs_in_sec(&s2, Some(&g)), 1);
}

#[test]
fn the_usable_blocks_of_a_section_sum_to_its_capacity() {
    let s = sb();
    let per_seg = s.blks_per_seg();
    let mut s2 = s.clone();
    s2.segs_per_sec = 4;
    // Lose a segment and a bit: one whole segment gone, one short, two whole.
    let g = geom(&s2, per_seg + 7);
    let total: u32 = (0..4).map(|i| usable_blks_in_seg(&s2, Some(&g), i)).sum();
    assert_eq!(total, cap_blks_per_sec(&s2, Some(&g)));
}

#[test]
fn the_loss_repeats_in_every_section() {
    let s = sb();
    let per_seg = s.blks_per_seg();
    let mut s2 = s.clone();
    s2.segs_per_sec = 2;
    let g = geom(&s2, 5);
    for sec in 0..3u32 {
        assert_eq!(usable_blks_in_seg(&s2, Some(&g), sec * 2), per_seg);
        assert_eq!(usable_blks_in_seg(&s2, Some(&g), sec * 2 + 1), per_seg - 5);
    }
}
