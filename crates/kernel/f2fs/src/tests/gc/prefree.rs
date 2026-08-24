//! Segments that are empty but not yet free, proved against the medium.
//!
//! The property under test is a crash property, so the proof is a crash: the
//! image bytes are taken WITHOUT a checkpoint and mounted again, which is
//! exactly what a machine that died would find. A volume that hands a cleaned
//! segment straight back to the allocator passes every in-memory check and
//! loses the file here, because the checkpoint on the medium still points into
//! the segment the allocator wrote over.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, MAIN_BLKADDR, ROOT_INO, SEG_MAIN};
use crate::uapi::*;
use crate::volume::{map::Mapped, NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 11);
const FILE_BLOCKS: usize = 4;

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

fn whole(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    v.read_whole(&inode, ino).unwrap()
}

fn payload(blocks: usize) -> Vec<u8> {
    (0..blocks * BLKSIZE).map(|i| ((i / BLKSIZE) * 71 + (i % 253)) as u8).collect()
}

/// Mount the bytes as they stand, which is what a crash right now would
/// leave. No checkpoint is written on the way out.
fn crash_mount(v: Volume<MemImage>) -> Volume<MemImage> {
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// A volume whose last checkpoint names a four-block file, with that file's
/// data segment closed and cleanable.
fn committed_victim() -> (Volume<MemImage>, u32, u32, Vec<u8>) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let data = payload(FILE_BLOCKS);
    v.write_file(ino, 0, &data).unwrap();
    v.sync_data().unwrap();
    let victim = seg_of(addr_of(&v, ino, 0));
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    // The checkpoint that makes the victim's blocks state a crash returns to.
    v.commit().unwrap();
    (v, ino, victim, data)
}

/// Whether any hint at all would send the allocator into `segno`.
fn allocator_would_take(v: &Volume<MemImage>, segno: u32) -> bool {
    (0..SEG_MAIN).any(|h| v.find_free_seg(h) == Some(segno))
}

#[test]
fn a_cleaned_segment_is_empty_and_still_not_free() {
    let (mut v, ino, victim, _) = committed_victim();
    v.write_file(ino, 0, b"AAAA").unwrap();
    v.sync_data().unwrap();
    v.gc_segment(victim).unwrap();
    assert_eq!(v.seg_valid(victim), 0, "the cleaner emptied it");
    assert!(v.is_prefree(victim), "and is holding it");
    assert_eq!(v.prefree_count(), 1);
    assert!(!allocator_would_take(&v, victim), "no hint may reach it");
}

#[test]
fn a_held_segment_is_not_counted_as_free_space() {
    let (mut v, ino, victim, _) = committed_victim();
    let before = v.free_segment_count();
    v.write_file(ino, 0, b"AAAA").unwrap();
    v.sync_data().unwrap();
    v.gc_segment(victim).unwrap();
    assert_eq!(v.free_segment_count(), before, "an emptied segment is not free space");
    v.commit().unwrap();
    assert_eq!(v.free_segment_count(), before + 1, "the checkpoint made it space");
}

#[test]
fn the_checkpoint_hands_it_back_and_the_medium_agrees() {
    let (mut v, ino, victim, _) = committed_victim();
    v.write_file(ino, 0, b"AAAA").unwrap();
    v.sync_data().unwrap();
    v.gc_segment(victim).unwrap();
    assert!(v.is_prefree(victim));
    v.commit().unwrap();
    assert!(!v.is_prefree(victim), "the checkpoint retired the references");
    assert_eq!(v.prefree_count(), 0);
    assert!(allocator_would_take(&v, victim));
    // The bytes, mounted again: a fresh mount holds nothing prefree, because
    // the checkpoint it reads is the one that retired those blocks.
    let mut back = crash_mount(v);
    back.load_segments().unwrap();
    assert_eq!(back.seg_valid(victim), 0);
    assert!(!back.is_prefree(victim));
    assert!(allocator_would_take(&back, victim));
}

#[test]
fn a_crash_after_cleaning_still_reads_the_checkpointed_file() {
    let (mut v, ino, victim, data) = committed_victim();
    let committed: Vec<u32> = (0..FILE_BLOCKS as u64).map(|i| addr_of(&v, ino, i)).collect();
    for a in &committed { assert_eq!(seg_of(*a), victim); }
    // Kill one copy, clean the rest out, then keep allocating. Every block
    // written from here must go somewhere else: the checkpoint on the medium
    // still names all four blocks above.
    v.write_file(ino, 0, b"AAAA").unwrap();
    v.sync_data().unwrap();
    v.gc_segment(victim).unwrap();
    let other = v.create(ROOT_INO, b"g", &spec(), None).unwrap();
    let filler = payload(6);
    v.write_file(other, 0, &filler).unwrap();
    v.sync_data().unwrap();
    for i in 0..6u64 { v.write_file(other, i * BLKSIZE as u64, b"zzzz").unwrap(); }
    for i in 0..FILE_BLOCKS as u64 {
        assert_ne!(seg_of(addr_of(&v, other, i.min(5))), victim, "a write landed in the victim");
    }
    // The crash. What comes back is the last checkpoint, and the file it
    // named is still there because nothing overwrote it.
    let back = crash_mount(v);
    assert_eq!(whole(&back, ino), data, "the checkpointed file did not survive");
    for (i, a) in committed.iter().enumerate() {
        assert_eq!(addr_of(&back, ino, i as u64), *a, "the recovered file moved");
    }
}

#[test]
fn a_segment_emptied_by_ordinary_rewrites_is_held_too() {
    // Prefree is not a cleaner feature. Any segment that empties was named by
    // the checkpoint on the medium a moment ago.
    let (mut v, ino, victim, _) = committed_victim();
    for i in 0..FILE_BLOCKS as u64 {
        v.write_file(ino, i * BLKSIZE as u64, b"QQQQ").unwrap();
        v.sync_data().unwrap();
    }
    assert_eq!(v.seg_valid(victim), 0, "every copy was rewritten out of place");
    assert!(v.is_prefree(victim));
    assert!(!allocator_would_take(&v, victim));
}

#[test]
fn a_log_leaving_an_empty_segment_holds_it() {
    // A segment emptied while its own log is writing into it is not prefree
    // at that moment — the log is still appending — so the hold has to be
    // taken when the log leaves, or the segment goes back to the allocator
    // with the checkpoint still pointing into it.
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &payload(1)).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    let seg = seg_of(addr_of(&v, ino, 0));
    assert!(v.is_current(seg), "the log is still in it");
    v.truncate_file(ino, 0).unwrap();
    assert_eq!(v.seg_valid(seg), 0);
    assert!(!v.is_prefree(seg), "not while the log holds it");
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    assert!(v.is_prefree(seg), "held the moment the log left");
    assert!(!allocator_would_take(&v, seg));
}

#[test]
fn the_cleaner_takes_a_checkpoint_when_cleaning_alone_leaves_no_room() {
    let (mut v, ino, victim, _) = committed_victim();
    v.write_file(ino, 0, b"AAAA").unwrap();
    v.sync_data().unwrap();
    let before = v.free_segment_count();
    // Cleaning produces prefree segments, which are not free. Meeting a
    // target therefore takes the checkpoint that turns them into space.
    let freed = v.collect(before + 1).unwrap();
    assert_eq!(freed, 1);
    assert_eq!(v.prefree_count(), 0, "the cleaner retired what it freed");
    assert!(v.free_segment_count() > before);
    assert!(allocator_would_take(&v, victim));
}

#[test]
fn a_checkpoint_is_worth_taking_once_enough_is_held() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.load_segments().unwrap();
    assert!(!v.excess_prefree(), "nothing held");
    // The threshold is a share of the volume, so on this fixture a single
    // held segment already exceeds it.
    for s in 0..SEG_MAIN { if v.seg_is_free(s) { v.retire_segment(s); break; } }
    assert_eq!(v.prefree_count(), 1);
    assert!(v.excess_prefree());
}

#[test]
fn balancing_a_volume_short_of_room_finds_some_and_retires_it() {
    let (mut v, ino, victim, _) = committed_victim();
    v.write_file(ino, 0, b"AAAA").unwrap();
    v.sync_data().unwrap();
    assert!(!v.has_enough_free_secs(0, 0), "the fixture is at the reserve");
    v.balance_fs(true, false).unwrap();
    assert_eq!(v.seg_valid(victim), 0, "the cleaner emptied the best victim");
    assert_eq!(v.prefree_count(), 0, "and nothing was left held");
    assert!(v.has_enough_free_secs(0, 0), "there is room to allocate again");
}

#[test]
fn a_read_only_mount_balances_nothing() {
    let mut v = test_image::with_root().mount().unwrap();
    assert!(!v.writable());
    v.balance_fs(true, false).unwrap();
    v.balance_fs_bg(true, false).unwrap();
    assert_eq!(v.prefree_count(), 0);
}

#[test]
fn nothing_is_held_across_a_mount() {
    // The map is memory only, and it has to be: the checkpoint a mount reads
    // is the one that retired every reference an empty segment could have.
    let (mut v, ino, victim, _) = committed_victim();
    v.write_file(ino, 0, b"AAAA").unwrap();
    v.sync_data().unwrap();
    v.gc_segment(victim).unwrap();
    v.commit().unwrap();
    let held = v.prefree_count();
    let mut back = crash_mount(v);
    back.load_segments().unwrap();
    assert_eq!(held, 0);
    assert_eq!(back.prefree_count(), 0);
    let free_now = back.free_segment_count();
    assert!(free_now > 0);
    // And the freed segment is usable straight away in the new mount.
    let ino2 = back.create(ROOT_INO, b"h", &spec(), None).unwrap();
    back.write_file(ino2, 0, &vec![7u8; BLKSIZE]).unwrap();
    back.sync_data().unwrap();
    assert_eq!(whole(&back, ino2).len(), BLKSIZE);
}

#[test]
fn cleaning_ahead_of_demand_picks_a_victim_and_moves_the_cursor_on() {
    use crate::volume::gc::victim::Policy;
    let (mut v, ino, victim, _) = committed_victim();
    v.write_file(ino, 0, b"AAAA").unwrap();
    v.sync_data().unwrap();
    let expect = whole(&v, ino);
    assert_eq!(v.pick_victim(Policy::Greedy, &[]), Some(victim));
    assert_eq!(v.gc_background().unwrap(), Some(victim));
    assert_eq!(v.seg_valid(victim), 0, "the section was cleaned");
    assert!(v.is_prefree(victim), "and held, because no checkpoint was taken");
    // The next search starts past what this one took, so a volume cleaned in
    // the background sweeps rather than circling the same section.
    assert_eq!(v.gc_background().unwrap(), None, "nothing else is worth it");
    assert_eq!(whole(&v, ino), expect, "the file is intact either way");
}

#[test]
fn cleaning_ahead_of_demand_is_refused_on_a_read_only_mount() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.gc_background(), Err(syscall::errno::Errno::Erofs));
}
