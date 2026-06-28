//! `(major,minor)` cdev/bdev region registry (Linux `cdev_add`/`cdev_map`
//! `kobj_lookup`). Before this the registry keyed purely by MAJOR, so a single
//! driver grabbed an entire major and two drivers could never share one — wrong
//! for major 10 "misc", major 4 ttys/consoles, etc. This proves: disjoint minor
//! ranges on one major route by the COVERING range, an overlapping registration
//! is rejected `EBUSY`, `count == 0` is `EINVAL`, unregister drops only the
//! named slice, and the legacy whole-major claim still covers every minor.
//!
//! Each test uses a distinct major so the shared global registry needs no
//! serial guard (parallel tests touch disjoint keys).

use std::sync::Arc;

use vfs::devnode::{
    lookup_blkdev, lookup_chrdev, register_blkdev_region, register_chrdev,
    register_chrdev_region, unregister_blkdev, unregister_chrdev,
    unregister_chrdev_region, MINOR_SPAN,
};
use vfs::{BlockDevOps, CharDevOps, Devt, KResult, VfsError};

/// Char driver tagged by a byte its `read` returns, so a lookup-then-read
/// reveals which region answered.
struct TagChar(u8);
impl CharDevOps for TagChar {
    fn read(&self, _d: Devt, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if !buf.is_empty() { buf[0] = self.0; }
        Ok(1)
    }
}
struct TagBlk(u8);
impl BlockDevOps for TagBlk {
    fn read(&self, _d: Devt, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if !buf.is_empty() { buf[0] = self.0; }
        Ok(1)
    }
}

/// Lookup `(major,minor)` and read its tag byte (panics if no region covers it).
fn tag_at(major: u32, minor: u32) -> u8 {
    let drv = lookup_chrdev(Devt::new(major, minor)).expect("a region covers this minor");
    let mut b = [0u8; 1];
    drv.read(Devt::new(major, minor), 0, &mut b).unwrap();
    b[0]
}

#[test]
fn disjoint_minor_ranges_share_a_major() {
    let major = 200;
    register_chrdev_region(major, 0, 4, Arc::new(TagChar(0xAA))).unwrap(); // minors 0..4
    register_chrdev_region(major, 4, 4, Arc::new(TagChar(0xBB))).unwrap(); // minors 4..8
    assert_eq!(tag_at(major, 0), 0xAA, "minor 0 → first region");
    assert_eq!(tag_at(major, 3), 0xAA, "minor 3 (last of first range) → first region");
    assert_eq!(tag_at(major, 4), 0xBB, "minor 4 (first of second range) → second region");
    assert_eq!(tag_at(major, 7), 0xBB, "minor 7 → second region");
    assert!(lookup_chrdev(Devt::new(major, 8)).is_none(), "minor 8 is past both ranges → no driver");
    unregister_chrdev(major);
    assert!(lookup_chrdev(Devt::new(major, 0)).is_none(), "whole-major unregister clears every region");
}

#[test]
fn overlapping_registration_is_ebusy() {
    let major = 201;
    register_chrdev_region(major, 0, 4, Arc::new(TagChar(1))).unwrap();
    assert_eq!(
        register_chrdev_region(major, 2, 6, Arc::new(TagChar(2))),
        Err(VfsError::Ebusy),
        "an overlapping minor slice is rejected EBUSY",
    );
    // An adjacent (disjoint) slice is fine — half-open ranges don't touch.
    register_chrdev_region(major, 4, 4, Arc::new(TagChar(3))).unwrap();
    unregister_chrdev(major);
}

#[test]
fn zero_count_region_is_einval() {
    let major = 202;
    assert_eq!(
        register_chrdev_region(major, 0, 0, Arc::new(TagChar(1))),
        Err(VfsError::Einval),
        "a zero-length region is rejected EINVAL",
    );
    assert!(lookup_chrdev(Devt::new(major, 0)).is_none(), "a rejected register leaves the major empty");
}

#[test]
fn unregister_region_drops_only_that_slice() {
    let major = 203;
    register_chrdev_region(major, 0, 4, Arc::new(TagChar(0xA1))).unwrap();
    register_chrdev_region(major, 4, 4, Arc::new(TagChar(0xB2))).unwrap();
    unregister_chrdev_region(major, 0, 4);
    assert!(lookup_chrdev(Devt::new(major, 1)).is_none(), "the dropped slice no longer resolves");
    assert_eq!(tag_at(major, 5), 0xB2, "the surviving slice still resolves");
    unregister_chrdev(major);
}

#[test]
fn legacy_whole_major_claim_covers_every_minor() {
    let major = 204;
    register_chrdev(major, Arc::new(TagChar(0xCC)));
    assert_eq!(tag_at(major, 0), 0xCC, "minor 0 covered");
    assert_eq!(tag_at(major, MINOR_SPAN - 1), 0xCC, "the highest minor is covered");
    // A whole-major claim occupies [0, MINOR_SPAN); any region register overlaps.
    assert_eq!(
        register_chrdev_region(major, 0, 4, Arc::new(TagChar(1))),
        Err(VfsError::Ebusy),
        "a slice register over a whole-major claim is EBUSY",
    );
    unregister_chrdev(major);
}

#[test]
fn block_region_routes_by_minor_too() {
    let major = 205;
    register_blkdev_region(major, 0, 2, Arc::new(TagBlk(0xD1))).unwrap();
    register_blkdev_region(major, 16, 2, Arc::new(TagBlk(0xD2))).unwrap(); // e.g. /dev/sda vs /dev/sdb base
    let read_tag = |minor: u32| {
        let drv = lookup_blkdev(Devt::new(major, minor)).expect("region covers minor");
        let mut b = [0u8; 1];
        drv.read(Devt::new(major, minor), 0, &mut b).unwrap();
        b[0]
    };
    assert_eq!(read_tag(1), 0xD1);
    assert_eq!(read_tag(17), 0xD2);
    assert!(lookup_blkdev(Devt::new(major, 8)).is_none(), "gap between block ranges → no driver");
    unregister_blkdev(major);
}
