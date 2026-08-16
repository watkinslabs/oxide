//! The allocator's truth: which blocks are live and which segments are free.

use super::*;
use crate::summary::SitEntry;
use crate::test_image::{self, nodes};
use alloc::vec;

/// A writable fixture volume with an empty root.
fn vol() -> crate::volume::Volume<sectors::MemImage> {
    test_image::with_root().mount_rw().unwrap()
}

#[test]
fn a_blank_entry_has_nothing_live() {
    let e = empty_entry();
    assert_eq!(e.valid_blocks(), 0);
    assert!(!e.is_valid(0));
}

#[test]
fn the_table_loads_what_the_fixture_wrote() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"x");
    let want = b.sit_valid[0];
    let mut v = b.mount_rw().unwrap();
    v.load_segments().unwrap();
    assert_eq!(v.seg_valid(0), want);
    assert_eq!(v.segments().len(), test_image::SEG_MAIN as usize);
}

#[test]
fn loading_twice_does_not_reload() {
    let mut v = vol();
    v.load_segments().unwrap();
    let before = v.seg_valid(0);
    v.load_segments().unwrap();
    assert_eq!(v.seg_valid(0), before);
}

#[test]
fn marking_a_block_live_raises_the_count_and_the_bit() {
    let mut v = vol();
    v.load_segments().unwrap();
    let addr = test_image::MAIN_BLKADDR + 40;
    let before = v.seg_valid(0);
    v.update_seg(addr, true).unwrap();
    assert_eq!(v.seg_valid(0), before + 1);
    assert!(v.block_is_live(addr).unwrap());
}

#[test]
fn releasing_a_block_lowers_the_count_and_clears_the_bit() {
    let mut v = vol();
    v.load_segments().unwrap();
    let addr = test_image::MAIN_BLKADDR + 41;
    v.update_seg(addr, true).unwrap();
    let before = v.seg_valid(0);
    v.update_seg(addr, false).unwrap();
    assert_eq!(v.seg_valid(0), before - 1);
    assert!(!v.block_is_live(addr).unwrap());
}

#[test]
fn marking_a_block_live_twice_counts_it_once() {
    // The pairing is what keeps the count honest; a double count leaves a
    // segment that never reads as free.
    let mut v = vol();
    v.load_segments().unwrap();
    let addr = test_image::MAIN_BLKADDR + 42;
    v.update_seg(addr, true).unwrap();
    let once = v.seg_valid(0);
    v.update_seg(addr, true).unwrap();
    assert_eq!(v.seg_valid(0), once);
}

#[test]
fn releasing_a_block_twice_lowers_the_count_once() {
    let mut v = vol();
    v.load_segments().unwrap();
    let addr = test_image::MAIN_BLKADDR + 43;
    v.update_seg(addr, true).unwrap();
    v.update_seg(addr, false).unwrap();
    let once = v.seg_valid(0);
    v.update_seg(addr, false).unwrap();
    assert_eq!(v.seg_valid(0), once);
}

#[test]
fn a_hole_is_not_a_block_and_changes_nothing() {
    let mut v = vol();
    v.load_segments().unwrap();
    let before = v.seg_valid(0);
    v.update_seg(NULL_ADDR, false).unwrap();
    v.update_seg(NEW_ADDR, false).unwrap();
    assert_eq!(v.seg_valid(0), before);
}

#[test]
fn a_second_segment_is_accounted_separately() {
    let mut v = vol();
    v.load_segments().unwrap();
    let addr = test_image::MAIN_BLKADDR + BLKS_PER_SEG + 3;
    let before = (v.seg_valid(0), v.seg_valid(1));
    v.update_seg(addr, true).unwrap();
    assert_eq!(v.seg_valid(0), before.0);
    assert_eq!(v.seg_valid(1), before.1 + 1);
}

#[test]
fn a_log_holds_its_own_segment_open() {
    let mut v = vol();
    v.load_segments().unwrap();
    v.open_segment(crate::uapi::CURSEG_HOT_NODE).unwrap();
    let seg = v.logs()[crate::uapi::CURSEG_HOT_NODE].segno;
    assert!(v.is_current(seg));
    assert_ne!(v.find_free_seg(0), Some(seg));
}

#[test]
fn a_free_segment_is_one_with_nothing_live() {
    let mut v = vol();
    v.load_segments().unwrap();
    let free = v.find_free_seg(0).unwrap();
    assert_eq!(v.seg_valid(free), 0);
}

#[test]
fn a_volume_with_every_segment_used_offers_none() {
    let mut v = vol();
    v.load_segments().unwrap();
    for seg in 0..test_image::SEG_MAIN {
        let base = test_image::MAIN_BLKADDR + seg * BLKS_PER_SEG;
        v.update_seg(base, true).unwrap();
    }
    assert_eq!(v.find_free_seg(0), None);
}

#[test]
fn a_recycling_candidate_is_partly_used_and_not_open() {
    let mut v = vol();
    v.load_segments().unwrap();
    // Put one block in a segment no log holds open, which is exactly the
    // shape recycling exists for.
    let victim = test_image::SEG_MAIN - 1;
    v.update_seg(test_image::MAIN_BLKADDR + victim * BLKS_PER_SEG + 2, true).unwrap();
    let (seg, off) = v.find_victim_seg(0).unwrap();
    assert_eq!(seg, victim);
    assert!(v.seg_valid(seg) > 0);
    assert!(v.seg_valid(seg) < BLKS_PER_SEG as u16);
    assert!(!v.segments()[seg as usize].is_valid(off as usize));
}

#[test]
fn a_segment_a_log_holds_open_is_never_recycled() {
    // Handing a log's own segment to another log would give both the same
    // blocks.
    let mut v = vol();
    v.load_segments().unwrap();
    for log in 0..NR_CURSEG_PERSIST_TYPE {
        let seg = v.logs()[log].segno;
        v.update_seg(test_image::MAIN_BLKADDR + seg * BLKS_PER_SEG + 300, true).unwrap();
    }
    assert_eq!(v.find_victim_seg(0), None);
}

#[test]
fn an_empty_segment_is_not_a_recycling_candidate() {
    // Recycling an empty segment is what opening a fresh one already does.
    let mut v = vol();
    v.load_segments().unwrap();
    assert_eq!(v.find_victim_seg(0), None);
}

#[test]
fn the_first_free_block_skips_the_live_ones() {
    let mut v = vol();
    v.load_segments().unwrap();
    let used = v.seg_valid(0);
    assert_eq!(v.first_free_block(0), Some(used));
}

#[test]
fn the_next_free_block_starts_where_it_is_told() {
    let mut v = vol();
    v.load_segments().unwrap();
    assert_eq!(v.next_free_block(0, 100), Some(100));
    assert_eq!(v.next_free_block(0, BLKS_PER_SEG as u16), None);
}

#[test]
fn the_free_segment_count_matches_the_table() {
    let mut v = vol();
    v.load_segments().unwrap();
    // A segment a log holds open is not free however empty it is: the log
    // will fill it, and counting it would offer the allocator a segment that
    // is already spoken for.
    let by_hand = (0..test_image::SEG_MAIN)
        .filter(|&s| v.seg_valid(s) == 0 && !v.is_current(s))
        .count() as u32;
    assert_eq!(v.free_segment_count(), by_hand);
    assert!((0..test_image::SEG_MAIN).any(|s| v.is_current(s) && v.seg_valid(s) == 0),
            "no empty open segment, so the exclusion is untested");
}

#[test]
fn only_changed_segments_are_reported_dirty() {
    let mut v = vol();
    v.load_segments().unwrap();
    assert!(v.dirty_segments().is_empty());
    v.update_seg(test_image::MAIN_BLKADDR + 50, true).unwrap();
    let dirty = v.dirty_segments();
    assert_eq!(dirty.len(), 1);
    assert_eq!(dirty[0].0, 0);
}

#[test]
fn a_table_block_round_trips_its_entries() {
    let mut e = SitEntry { vblocks: 3, valid_map: [0u8; SIT_VBLOCK_MAP_SIZE], mtime: 77 };
    e.valid_map[0] = 0b0000_0111;
    let block = sit_block(&[(1, e.clone())]);
    let (_, off) = crate::sit::locate(1);
    let back = crate::summary::sit_entry(&block, off).unwrap();
    assert_eq!(back, e);
}

#[test]
fn a_table_block_leaves_other_slots_alone() {
    let e = SitEntry { vblocks: 3, valid_map: [0xFFu8; SIT_VBLOCK_MAP_SIZE], mtime: 1 };
    let block = sit_block(&[(1, e)]);
    let (_, off) = crate::sit::locate(0);
    assert_eq!(&block[off..off + SIT_ENTRY_SIZE], &vec![0u8; SIT_ENTRY_SIZE][..]);
}
