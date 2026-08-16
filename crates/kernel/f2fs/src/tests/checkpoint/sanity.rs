//! The layout figures a formatter writes, and the volumes they refuse.

use crate::checkpoint::sanity::{check, LayoutError, MIN_META_SEGMENTS};
use crate::checkpoint::Checkpoint;
use crate::flags::FEATURE_RO;
use crate::sb::SuperBlock;
use crate::test_image::{self as image, SEG_CKPT, SEG_MAIN, SEG_NAT, SEG_SIT, SEG_SSA};
use crate::uapi::{SUPER_OFFSET, SUPER_SIZE};

/// The fixture's superblock, which is the shape a formatter leaves.
fn sb() -> SuperBlock {
    let bytes = image::Builder::new().finish();
    crate::sb::parse(&bytes[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE]).expect("parses")
}

/// A checkpoint carrying the two figures under test and nothing else that
/// matters here.
fn cp(rsvd: u32, ovp: u32) -> Checkpoint {
    Checkpoint { rsvd_segment_count: rsvd, overprov_segment_count: ovp, ..blank() }
}

fn blank() -> Checkpoint {
    let bytes = image::Builder::new().finish();
    let at = crate::test_image::CP_BLKADDR as usize * crate::uapi::BLKSIZE;
    crate::checkpoint::parse(&bytes[at..at + crate::uapi::BLKSIZE], crate::checkpoint::Pack::First)
        .expect("the fixture's own checkpoint parses")
}

#[test]
fn the_fixture_is_a_volume_a_formatter_could_have_written() {
    check(&blank(), &sb()).expect("the fixture must not be a volume the mount refuses");
    assert_eq!(SEG_CKPT + SEG_SIT + SEG_NAT + SEG_SSA + 1, MIN_META_SEGMENTS,
               "the fixture sits exactly on the smallest layout the format defines");
}

/// A volume holding nothing back for the cleaner has nowhere to move live
/// blocks to, so it is refused rather than mounted with a floor substituted.
#[test]
fn a_volume_with_no_reserve_is_refused() {
    // The fixture sits exactly on the smallest layout WITH its reserve
    // counted, so taking the reserve away also takes it under the floor. One
    // more table segment separates the two refusals.
    let s = SuperBlock { segment_count_nat: SEG_NAT + 1, ..sb() };
    assert_eq!(check(&cp(0, 1), &s), Err(LayoutError::NoReserve));
    // Both wrong at once reports the floor, which is the coarser fault.
    assert_eq!(check(&cp(0, 1), &sb()), Err(LayoutError::MetaTooSmall));
}

#[test]
fn a_volume_with_no_over_provisioning_is_refused() {
    assert_eq!(check(&cp(1, 0), &sb()), Err(LayoutError::NoOverprovision));
}

/// A volume the format marks read-only never allocates and never cleans, and
/// its formatter writes neither figure.
#[test]
fn a_read_only_volume_needs_neither() {
    let ro = SuperBlock { feature: sb().feature | FEATURE_RO, ..sb() };
    check(&cp(0, 0), &ro).expect("a read-only volume reserves nothing");
}

/// Metadata and reserve that claim the whole volume leave no main area, and
/// that is refused whatever the volume's features say.
#[test]
fn metadata_that_claims_the_whole_volume_is_refused() {
    let s = sb();
    let all = s.segment_count;
    assert_eq!(check(&cp(all, 1), &s), Err(LayoutError::MetaTooLarge));
    let ro = SuperBlock { feature: s.feature | FEATURE_RO, ..s };
    assert_eq!(check(&cp(all, 1), &ro), Err(LayoutError::MetaTooLarge));
}

/// Less metadata than the smallest layout the format defines is a volume no
/// formatter wrote.
#[test]
fn a_layout_smaller_than_the_format_defines_is_refused() {
    let s = SuperBlock { segment_count_nat: 0, segment_count_sit: 0, ..sb() };
    assert_eq!(check(&cp(1, 1), &s), Err(LayoutError::MetaTooSmall));
}

/// The main area is untouched by any of this: the figures come out of the
/// checkpoint and the metadata areas out of the superblock.
#[test]
fn the_main_area_is_not_part_of_the_sum() {
    let s = SuperBlock { segment_count_main: SEG_MAIN * 4, ..sb() };
    check(&cp(1, 1), &s).expect("a bigger main area refuses nothing");
}

/// The check is not a pure function nobody calls: a volume whose formatter
/// left no reserve is refused by the MOUNT.
#[test]
fn a_volume_with_no_reserve_does_not_mount() {
    use crate::opts::Options;
    use crate::volume::Volume;
    let mut b = image::with_root();
    b.rsvd_segments = 0;
    assert_eq!(Volume::mount_with(b.image(), Options::defaults(), true).err(),
               Some(syscall::errno::Errno::Einval));
    // The same volume with the reserve its formatter should have written
    // mounts, so it is the figure that is refused and not the fixture.
    assert!(Volume::mount_with(image::with_root().image(), Options::defaults(), true).is_ok());
}

/// And one with no over-provisioning likewise.
#[test]
fn a_volume_with_no_over_provisioning_does_not_mount() {
    use crate::opts::Options;
    use crate::volume::Volume;
    let mut b = image::with_root();
    b.overprov_segments = 0;
    assert_eq!(Volume::mount_with(b.image(), Options::defaults(), true).err(),
               Some(syscall::errno::Errno::Einval));
}
