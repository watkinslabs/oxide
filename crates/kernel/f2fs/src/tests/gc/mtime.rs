//! When a segment was written, and what depends on knowing.
//!
//! A timestamp nobody stamps is a timestamp every segment shares, and a policy
//! that weighs age against liveness then has no age to weigh: it degenerates
//! to whichever segment happens to sort first. These tests hold the stamping
//! and the policy that consumes it together, because either alone looks fine.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, MAIN_BLKADDR, ROOT_INO};
use crate::uapi::*;
use crate::volume::gc::victim::Policy;
use crate::volume::{map::Mapped, NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 11);
/// The wall clock the fixture mounts at. Ages are counted from here.
const MOUNTED_AT: u64 = 1_800_000_000;

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

fn seg_of(addr: u32) -> u32 { (addr - MAIN_BLKADDR) / BLKS_PER_SEG }

fn addr_of(v: &Volume<MemImage>, ino: u32, index: u64) -> u32 {
    let inode = v.read_inode(ino).unwrap();
    match v.map_block(&inode, ino, index).unwrap() {
        Mapped::At(a) => a,
        _ => panic!("the file's block is not a block"),
    }
}

/// A writable volume that has been told the time.
fn clocked() -> Volume<MemImage> {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.set_clock(MOUNTED_AT);
    v
}

/// Write one block into a file of its own and hand back the segment it landed
/// in, having closed that segment so nothing else is appended to it.
fn seal_a_segment(v: &mut Volume<MemImage>, name: &[u8], at: u64) -> u32 {
    v.set_clock(at);
    let ino = v.create(ROOT_INO, name, &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![0xA5u8; BLKSIZE]).unwrap();
    let seg = seg_of(addr_of(v, ino, 0));
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    seg
}

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

#[test]
fn the_volumes_own_clock_counts_from_the_mount() {
    let mut v = clocked();
    assert_eq!(v.seg_mtime_now(), 0, "a volume made now is no seconds old");
    v.set_clock(MOUNTED_AT + 500);
    assert_eq!(v.seg_mtime_now(), 500);
    // A clock set backwards takes the volume back with it, and stops at the
    // age it was made: nothing on it can be older than that.
    v.set_clock(MOUNTED_AT - 10);
    assert_eq!(v.seg_mtime_now(), 0);
}

#[test]
fn a_clock_set_backwards_takes_an_older_volume_back_with_it() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    // A volume that has been around a while before this mount.
    v.segstate.elapsed_base = 10_000;
    v.set_clock(MOUNTED_AT);
    assert_eq!(v.seg_mtime_now(), 10_000);
    v.set_clock(MOUNTED_AT + 60);
    assert_eq!(v.seg_mtime_now(), 10_060);
    v.set_clock(MOUNTED_AT - 60);
    assert_eq!(v.seg_mtime_now(), 9_940, "the age follows the clock down");
    v.set_clock(MOUNTED_AT - 20_000);
    assert_eq!(v.seg_mtime_now(), 0, "and stops at the day it was made");
}

#[test]
fn a_volume_never_told_the_time_reports_the_age_it_was_mounted_with() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    assert_eq!(v.seg_mtime_now(), 0);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    assert_eq!(v.seg_mtime(seg_of(addr_of(&v, ino, 0))), 0);
}

#[test]
fn a_write_stamps_the_segment_it_lands_in() {
    let mut v = clocked();
    v.set_clock(MOUNTED_AT + 90);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![3u8; BLKSIZE]).unwrap();
    let seg = seg_of(addr_of(&v, ino, 0));
    assert_eq!(v.seg_mtime(seg), 90, "the segment carries when it was written");
}

#[test]
fn the_stamp_is_a_mean_over_the_blocks_the_segment_holds() {
    // Two blocks written a long way apart put the segment between them, so
    // one recent block cannot make an old segment look new.
    let mut v = clocked();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.set_clock(MOUNTED_AT + 100);
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    let seg = seg_of(addr_of(&v, ino, 0));
    let after_first = v.seg_mtime(seg);
    v.set_clock(MOUNTED_AT + 300);
    v.write_file(ino, BLKSIZE as u64, &vec![2u8; BLKSIZE]).unwrap();
    assert_eq!(seg_of(addr_of(&v, ino, 1)), seg, "both blocks are in the one segment");
    let after_second = v.seg_mtime(seg);
    assert!(after_second > after_first, "the newer block moved it forward");
    assert!(after_second < 300, "but not all the way: the older block still counts");
}

#[test]
fn the_stamp_reaches_the_medium() {
    let mut v = clocked();
    v.set_clock(MOUNTED_AT + 250);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![9u8; BLKSIZE]).unwrap();
    let seg = seg_of(addr_of(&v, ino, 0));
    let stamped = v.seg_mtime(seg);
    assert_ne!(stamped, 0);
    let mut back = remount(v);
    back.load_segments().unwrap();
    assert_eq!(back.seg_mtime(seg), stamped, "the segment table carried it");
}

#[test]
fn the_checkpoint_records_how_old_the_volume_got() {
    let mut v = clocked();
    v.set_clock(MOUNTED_AT + 400);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![4u8; BLKSIZE]).unwrap();
    let mut back = remount(v);
    assert_eq!(back.checkpoint().elapsed_time, 400, "the volume is 400 seconds old");
    // And the next mount counts from there rather than from zero.
    back.set_clock(MOUNTED_AT + 1000);
    back.set_clock(MOUNTED_AT + 1030);
    assert_eq!(back.seg_mtime_now(), 430);
}

#[test]
fn cleaning_does_not_make_the_data_it_moves_look_new() {
    // A migration is not a write. Stamping the destination with now would
    // make every cleaned segment the youngest on the volume, which is the
    // one thing age-aware selection must not believe.
    let mut v = clocked();
    let old = seal_a_segment(&mut v, b"old", MOUNTED_AT + 10);
    assert_eq!(v.seg_mtime(old), 10, "written long ago");
    // The log has moved to an empty segment, so whatever age it ends up with
    // is the age the migration gave it: an empty segment holds no blocks for
    // the mean to weigh, so the first stamp is the answer outright.
    let dest = v.logs()[CURSEG_WARM_DATA].segno;
    assert_eq!(v.seg_valid(dest), 0, "the destination starts empty");
    v.set_clock(MOUNTED_AT + 5_000);
    let moved = v.gc_segment(old).unwrap();
    assert!(moved > 0, "there was something to move");
    assert_eq!(v.seg_mtime(dest), 10, "the copy is as old as the data it copied");
    assert_eq!(v.seg_mtime(old), 10, "and emptying the victim is not a write either");
}

#[test]
fn cost_benefit_needs_the_stamp_to_tell_two_segments_apart() {
    // The whole point of stamping. Two segments equally live, written a long
    // way apart: the older one is the one whose blocks are least likely to
    // die on their own, so it is the one worth cleaning.
    // The two candidates are made by marking blocks live directly, because
    // the fixture volume is too small to hold two closed segments without the
    // allocator cleaning one of them out from under the test.
    let mut v = clocked();
    v.load_segments().unwrap();
    // The older one is deliberately the HIGHER-numbered segment, so an
    // answer that ignores the stamps cannot be right by accident.
    let (younger, older) = (test_image::SEG_MAIN - 2, test_image::SEG_MAIN - 1);
    for (seg, at) in [(younger, 9_000u64), (older, 10)] {
        v.set_clock(MOUNTED_AT + at);
        for b in 0..4u32 {
            v.update_seg(MAIN_BLKADDR + seg * BLKS_PER_SEG + b, true).unwrap();
        }
    }
    assert!(!v.is_current(younger) && !v.is_current(older));
    assert_eq!(v.seg_valid(younger), v.seg_valid(older), "equally live");
    assert!(v.seg_mtime(older) < v.seg_mtime(younger), "and told apart by age");
    let picked = v.pick_victim(Policy::CostBenefit, &[]).unwrap();
    assert_eq!(picked, older, "the older segment is the victim");
    // With no stamps to read the same table gives the lowest segment number
    // whatever its age, which is what an unstamped volume degenerates to.
    let table = v.seg_table();
    let flat: Vec<_> = table.iter().map(|s| crate::volume::gc::SegInfo { mtime: 0, ..*s }).collect();
    let per = v.super_block().blks_per_seg() as u16;
    let blind = crate::volume::gc::victim::pick(&flat, per, Policy::CostBenefit, &[]).unwrap();
    assert_ne!(blind, older, "unstamped selection cannot find the older segment");
    assert_eq!(blind, younger, "it takes the first candidate it reaches instead");
}
