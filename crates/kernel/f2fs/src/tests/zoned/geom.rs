//! The figures the reports agree on, and the disagreements.

use alloc::vec;
use alloc::vec::Vec;

use crate::flags::FEATURE_BLKZONED;
use crate::zoned::geom::{paths_ok, OPEN_ZONES_UNBOUNDED};
use crate::zoned::{DevZones, Geometry, Zone, ZoneError, ZoneType};

const ZONED: u32 = FEATURE_BLKZONED;
const PLAIN: u32 = 0;

fn zone(start: u64, len: u32, cap: u32, kind: ZoneType) -> Zone {
    Zone { start_blk: start, len_blks: len, cap_blks: cap, kind }
}

/// `n` sequential zones of `len` blocks with `cap` usable.
fn seq(n: u64, len: u32, cap: u32) -> DevZones {
    let zones: Vec<Zone> =
        (0..n).map(|i| zone(i * u64::from(len), len, cap, ZoneType::SeqWriteRequired)).collect();
    DevZones { blocks_per_zone: len, max_open_zones: None, zones }
}

#[test]
fn a_drive_that_reports_nothing_leaves_no_blocks_unusable() {
    let g = Geometry::build(ZONED, &[None], 6).expect("builds");
    assert_eq!(g.unusable_blocks_per_sec, 0);
    assert!(!g.dev_is_zoned(0));
}

#[test]
fn an_empty_report_slice_is_the_same_answer_as_a_conventional_drive() {
    let a = Geometry::build(ZONED, &[], 6).expect("builds");
    let b = Geometry::build(ZONED, &[None], 6).expect("builds");
    assert_eq!(a.unusable_blocks_per_sec, b.unusable_blocks_per_sec);
    assert_eq!(a.dev_is_zoned(0), b.dev_is_zoned(0));
}

#[test]
fn a_short_capacity_becomes_the_unusable_figure() {
    let g = Geometry::build(ZONED, &[Some(seq(4, 512, 500))], 6).expect("builds");
    assert_eq!(g.unusable_blocks_per_sec, 12);
    assert_eq!(g.blocks_per_zone, 512);
    assert!(g.dev_is_zoned(0));
}

#[test]
fn conventional_zones_contribute_nothing_and_are_not_sequential() {
    let zones = vec![
        zone(0, 512, 512, ZoneType::Conventional),
        zone(512, 512, 512, ZoneType::Conventional),
    ];
    let r = DevZones { blocks_per_zone: 512, max_open_zones: None, zones };
    let g = Geometry::build(ZONED, &[Some(r)], 6).expect("builds");
    assert_eq!(g.unusable_blocks_per_sec, 0);
    assert!(!g.is_seq(0, 0));
    assert!(!g.is_seq(0, 1));
    assert_eq!(g.zone_count(0), 2);
}

#[test]
fn a_host_aware_zone_counts_as_sequential() {
    // The drive accepts a random write there and then moves it, which loses
    // the placement the filesystem chose.
    let zones = vec![zone(0, 512, 512, ZoneType::SeqWritePreferred)];
    let r = DevZones { blocks_per_zone: 512, max_open_zones: None, zones };
    let g = Geometry::build(ZONED, &[Some(r)], 6).expect("builds");
    assert!(g.is_seq(0, 0));
}

#[test]
fn zones_of_different_capacity_are_refused() {
    let zones = vec![
        zone(0, 512, 500, ZoneType::SeqWriteRequired),
        zone(512, 512, 480, ZoneType::SeqWriteRequired),
    ];
    let r = DevZones { blocks_per_zone: 512, max_open_zones: None, zones };
    assert_eq!(Geometry::build(ZONED, &[Some(r)], 6), Err(ZoneError::MixedCapacity));
}

#[test]
fn members_stating_different_zone_sizes_are_refused() {
    let reports = [Some(seq(2, 512, 512)), Some(seq(2, 1024, 1024))];
    assert_eq!(Geometry::build(ZONED, &reports, 6), Err(ZoneError::MixedZoneSize));
}

#[test]
fn a_drive_that_will_not_keep_enough_zones_open_is_refused() {
    let mut r = seq(4, 512, 512);
    r.max_open_zones = Some(4);
    assert_eq!(Geometry::build(ZONED, &[Some(r)], 6), Err(ZoneError::TooFewOpenZones));
}

#[test]
fn a_stated_limit_at_least_as_large_as_the_logs_is_accepted_and_kept() {
    let mut r = seq(4, 512, 512);
    r.max_open_zones = Some(8);
    let g = Geometry::build(ZONED, &[Some(r)], 6).expect("builds");
    assert_eq!(g.max_open_zones, 8);
}

#[test]
fn the_smallest_stated_limit_wins() {
    let mut a = seq(4, 512, 512);
    a.max_open_zones = Some(16);
    let mut b = seq(4, 512, 512);
    b.max_open_zones = Some(9);
    let g = Geometry::build(ZONED, &[Some(a), Some(b)], 6).expect("builds");
    assert_eq!(g.max_open_zones, 9);
}

#[test]
fn a_drive_stating_no_limit_leaves_the_bound_open() {
    let g = Geometry::build(ZONED, &[Some(seq(4, 512, 512))], 6).expect("builds");
    assert_eq!(g.max_open_zones, OPEN_ZONES_UNBOUNDED);
}

#[test]
fn a_zoned_drive_under_a_conventional_layout_is_refused() {
    // The format decides the layout; a zoned drive holding one that ignores
    // zones would be written wherever the filesystem liked.
    assert_eq!(Geometry::build(PLAIN, &[Some(seq(4, 512, 512))], 6), Err(ZoneError::FeatureOff));
}

#[test]
fn a_conventional_drive_under_a_conventional_layout_builds() {
    assert!(Geometry::build(PLAIN, &[None], 6).is_ok());
}

#[test]
fn a_zoned_layout_naming_no_member_on_a_drive_with_no_zones_is_refused() {
    // Nothing then says where the zones are, and reading it as though there
    // were none places blocks the drive will refuse.
    assert_eq!(paths_ok(ZONED, false, false), Err(ZoneError::PathMissing));
    assert!(paths_ok(ZONED, true, false).is_ok());
    assert!(paths_ok(ZONED, false, true).is_ok());
}

#[test]
fn a_conventional_layout_never_needs_a_path() {
    assert!(paths_ok(PLAIN, false, false).is_ok());
}

#[test]
fn a_member_that_reported_nothing_has_no_zones_at_any_index() {
    let g = Geometry::build(ZONED, &[None, Some(seq(2, 512, 500))], 6).expect("builds");
    assert_eq!(g.zone_count(0), 0);
    assert!(!g.is_seq(0, 0));
    assert!(g.is_seq(1, 0));
    assert!(!g.is_seq(1, 99));
    assert!(!g.is_seq(9, 0));
}
