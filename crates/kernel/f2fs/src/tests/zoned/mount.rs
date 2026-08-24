//! A zoned volume brought up against real reports.

use crate::flags::FEATURE_BLKZONED;
use crate::opts::Options;
use crate::test_image::{self as image, spread};

/// A zoned-layout fixture that names its members, so the layout is locatable
/// even from a drive that reports nothing.
fn zoned(devs: &[(&str, u32)]) -> image::Builder {
    let mut b = image::with_root().devices(devs);
    b.feature |= FEATURE_BLKZONED;
    b
}

#[test]
fn a_zoned_layout_is_no_longer_refused_at_mount() {
    let v = spread::mount(zoned(&[("/dev/a", 15)])).expect("zoned volume mounts");
    assert!(crate::features::has_blkzoned(v.super_block().feature));
    assert!(v.zones().is_some());
}

#[test]
fn a_conventional_drive_under_a_zoned_layout_loses_no_blocks() {
    // Every zone conventional is exactly what a drive reporting nothing is.
    let v = spread::mount(zoned(&[("/dev/a", 15)])).expect("mounts");
    let g = v.zones().expect("geometry");
    assert_eq!(g.unusable_blocks_per_sec, 0);
    assert_eq!(v.usable_blks_in_seg(0), v.super_block().blks_per_seg());
    assert_eq!(v.usable_segs_in_sec(), v.super_block().segs_per_sec);
}

#[test]
fn a_conventional_layout_carries_no_geometry_at_all() {
    let v = spread::mount(image::with_root().devices(&[("/dev/a", 15)])).expect("mounts");
    assert!(v.zones().is_none());
}

#[test]
fn a_zoned_layout_naming_no_member_is_refused_when_the_drive_reports_none() {
    let mut b = image::with_root();
    b.feature |= FEATURE_BLKZONED;
    let img = b.image();
    assert!(crate::volume::Volume::mount_with(img, Options::defaults(), true).is_err());
}

#[test]
fn a_short_capacity_report_reaches_the_volumes_usable_answers() {
    let b = zoned(&[("/dev/a", 15)]);
    let per_sec = {
        let s = image::Builder::new().finish();
        let sb = crate::sb::parse(
            &s[crate::uapi::SUPER_OFFSET..crate::uapi::SUPER_OFFSET + crate::uapi::SUPER_SIZE])
            .unwrap();
        sb.segs_per_sec * sb.blks_per_seg()
    };
    let report = spread::report(4, per_sec, per_sec - 6, 0);
    let v = spread::mount_zoned(b, &[Some(report)]).expect("mounts");
    let g = v.zones().expect("geometry");
    assert_eq!(g.unusable_blocks_per_sec, 6);
    assert_eq!(v.cap_blks_per_sec(), per_sec - 6);
    assert_eq!(v.usable_blks_in_seg(0), v.super_block().blks_per_seg() - 6);
}

#[test]
fn a_zoned_drive_under_a_conventional_layout_refuses_the_mount() {
    let b = image::with_root().devices(&[("/dev/a", 15)]);
    let report = spread::report(4, 512, 500, 0);
    assert!(spread::mount_zoned(b, &[Some(report)]).is_err());
}

#[test]
fn reports_that_disagree_refuse_the_mount() {
    let b = zoned(&[("/dev/a", 8), ("/dev/b", 7)]);
    let a = spread::report(4, 512, 500, 0);
    let c = spread::report(4, 1024, 1000, 0);
    assert!(spread::mount_zoned(b, &[Some(a), Some(c)]).is_err());
}

#[test]
fn a_zoned_volume_may_also_be_spread() {
    let v = spread::mount(zoned(&[("/dev/a", 8), ("/dev/b", 7)])).expect("mounts");
    assert!(v.devices().is_multi());
    assert!(v.zones().is_some());
}

#[test]
fn regular_allocation_policy_prefers_the_requested_zone_kind() {
    let per_sec = {
        let s = image::Builder::new().finish();
        let sb = crate::sb::parse(
            &s[crate::uapi::SUPER_OFFSET..crate::uapi::SUPER_OFFSET + crate::uapi::SUPER_SIZE])
            .unwrap();
        sb.segs_per_sec * sb.blks_per_seg()
    };
    let report = spread::report(4, per_sec, per_sec, 2);
    {
        let mut v = spread::mount_zoned(zoned(&[("/dev/a", 15)]), &[Some(report.clone())])
            .expect("mounts");
        v.load_segments().expect("segment map");
        v.set_blkzone_alloc_policy(crate::volume::zonewp::BLKZONE_ALLOC_PRIOR_CONV as u64)
            .expect("policy");
        v.open_new_section(crate::uapi::CURSEG_HOT_DATA).expect("new section");
        let seg = v.curseg_segno(crate::uapi::CURSEG_HOT_DATA);
        let first = crate::pin::section::section_first(seg, v.super_block().segs_per_sec);
        assert_eq!(v.section_is_sequential(first), Some(false));
    }
}
