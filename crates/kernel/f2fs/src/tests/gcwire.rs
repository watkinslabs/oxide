//! The allocator reaches the cleaner when it runs out of empty segments.
//!
//! The cleaner having tests of its own proves the cleaner works. It says
//! nothing about whether anything CALLS it — and for four lanes of this
//! filesystem, nothing did. These tests are about the call site.

use super::*;
use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};
use alloc::vec;
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 0);
const MAIN: u32 = test_image::MAIN_BLKADDR;

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A volume holding one genuinely part-used segment: two files were written
/// into the same log and one was deleted, so its blocks are dead and the
/// other's are live and must be MOVED before the segment can be reused.
fn part_used() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let dead = v.create(ROOT_INO, b"dead", &spec(), None).unwrap();
    let live = v.create(ROOT_INO, b"live", &spec(), None).unwrap();
    v.write_file(dead, 0, &vec![1u8; 40 * BLKSIZE]).unwrap();
    v.write_file(live, 0, &vec![2u8; 40 * BLKSIZE]).unwrap();
    v.remove(ROOT_INO, b"dead", false, NOW).unwrap();
    // Move the data log off that segment: a log still appending to a segment
    // holds it, and the cleaner must never take one out from under a writer.
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    (v, live)
}

/// Occupy every free segment but the reserve, which is the state a volume
/// reaches just before it would strand its own space.
fn nearly_full(v: &mut Volume<MemImage>) {
    v.load_segments().unwrap();
    let reserve = v.gc_reserve();
    let mut left = reserve;
    for seg in 0..test_image::SEG_MAIN {
        if v.is_current(seg) || v.seg_valid(seg) > 0 { continue; }
        if left > 0 { left -= 1; continue; }
        v.update_seg(MAIN + seg * BLKS_PER_SEG + 1, true).unwrap();
    }
    assert_eq!(v.free_segment_count(), reserve, "the fixture is not at the reserve");
}

#[test]
fn cleaning_moves_the_live_blocks_and_frees_the_segment() {
    let (mut v, live) = part_used();
    let before = v.free_segment_count();
    let freed = v.collect(before + 1).unwrap();
    assert!(freed >= 1, "the cleaner reclaimed nothing");
    // The victim is empty. The volume's free count need not have RISEN: the
    // blocks moved out had to land somewhere, which can cost a fresh segment.
    assert!((0..test_image::SEG_MAIN).any(|s| v.seg_valid(s) == 0));
    // The surviving file is unharmed, which is the whole point of moving
    // rather than dropping.
    let inode = v.read_inode(live).unwrap();
    assert_eq!(v.read_whole(&inode, live).unwrap(), vec![2u8; 40 * BLKSIZE]);
}

#[test]
fn opening_a_segment_at_the_reserve_cleans_rather_than_stranding_the_space() {
    // Reporting a full volume while free blocks sit in segments nobody is
    // writing to is the failure this call site exists to prevent.
    let (mut v, _) = part_used();
    nearly_full(&mut v);
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    assert_ne!(v.logs()[CURSEG_WARM_DATA].segno, NULL_SEGNO);
}

#[test]
fn a_write_that_needs_a_new_segment_still_succeeds() {
    let (mut v, live) = part_used();
    nearly_full(&mut v);
    let ino = v.create(ROOT_INO, b"more", &spec(), None).unwrap();
    let data = vec![0xA5u8; 4 * BLKSIZE];
    v.write_file(ino, 0, &data).unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), data);
    // And the file whose blocks the cleaner moved still reads.
    let inode = v.read_inode(live).unwrap();
    assert_eq!(v.read_whole(&inode, live).unwrap(), vec![2u8; 40 * BLKSIZE]);
}

#[test]
fn a_block_no_owner_claims_is_left_where_it_is() {
    // A segment-table bit with no node behind it is an inconsistency for a
    // checker to repair, not something the cleaner may move: writing its
    // address into a file would invent a reference that never existed.
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.load_segments().unwrap();
    let orphaned = test_image::SEG_MAIN - 1;
    v.update_seg(MAIN + orphaned * BLKS_PER_SEG + 1, true).unwrap();
    assert_eq!(v.gc_segment(orphaned).unwrap(), 0, "it moved a block nothing owns");
    assert_eq!(v.seg_valid(orphaned), 1);
}

#[test]
fn a_segment_a_log_holds_open_is_never_cleaned() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.load_segments().unwrap();
    let held = v.logs()[CURSEG_WARM_DATA].segno;
    assert_ne!(held, NULL_SEGNO);
    assert_eq!(v.gc_segment(held).err(), Some(Errno::Ebusy));
}

#[test]
fn a_volume_with_room_opens_a_segment_without_cleaning() {
    // The cleaner is the last resort, not the allocator's normal path.
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.load_segments().unwrap();
    let free_before = v.find_free_seg(0);
    assert!(free_before.is_some());
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    assert_eq!(v.logs()[CURSEG_WARM_DATA].segno, free_before.unwrap());
    assert_eq!(v.logs()[CURSEG_WARM_DATA].next_blkoff, 0);
}

#[test]
fn a_read_only_mount_cannot_be_made_to_clean() {
    let mut v = test_image::with_root().mount().unwrap();
    assert!(v.collect(1).is_err());
    assert!(v.gc_segment(0).is_err());
}
