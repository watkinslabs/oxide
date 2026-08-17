//! Adding and removing directory entries.

use super::*;
use crate::dirent::{block as deblock, Layout};
use crate::hash;
use crate::test_image::nodes::dir::{dentry_area, ent};
use alloc::vec;
use alloc::vec::Vec;

fn block_layout() -> Layout { Layout::block() }

#[test]
fn an_empty_area_offers_its_first_slot() {
    let area = vec![0u8; BLKSIZE];
    assert_eq!(room_for(&area, &block_layout(), 1), Some(0));
    assert_eq!(room_for(&area, &block_layout(), 4), Some(0));
}

#[test]
fn a_run_must_be_consecutive() {
    // Two free slots either side of a used one are not a run of two.
    let l = block_layout();
    let mut area = vec![0u8; BLKSIZE];
    area[0] = 0b0000_0010;
    assert_eq!(room_for(&area, &l, 1), Some(0));
    assert_eq!(room_for(&area, &l, 2), Some(2));
}

#[test]
fn a_full_area_offers_nothing() {
    let l = block_layout();
    let mut area = vec![0xFFu8; BLKSIZE];
    // Only the bitmap matters; clear the tail bits past the entry count.
    for i in l.max..l.bitmap_len * 8 { area[i / 8] &= !(1 << (i % 8)); }
    assert_eq!(room_for(&area, &l, 1), None);
}

#[test]
fn a_run_at_the_very_end_is_offered() {
    let l = block_layout();
    let mut area = vec![0u8; BLKSIZE];
    for i in 0..l.max - 2 { area[i / 8] |= 1 << (i % 8); }
    assert_eq!(room_for(&area, &l, 2), Some(l.max - 2));
    assert_eq!(room_for(&area, &l, 3), None);
}

#[test]
fn a_placed_entry_reads_back() {
    let l = block_layout();
    let mut area = vec![0u8; BLKSIZE];
    place_entry(&mut area, &l, 0, b"name", 42, FT_REG_FILE);
    let out = deblock::entries(&area, &l).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, b"name");
    assert_eq!(out[0].ino, 42);
    assert_eq!(out[0].hash, hash::name_hash(b"name"));
}

#[test]
fn a_placed_long_name_marks_every_slot_it_spans() {
    let l = block_layout();
    let mut area = vec![0u8; BLKSIZE];
    place_entry(&mut area, &l, 0, b"123456789", 7, FT_REG_FILE);
    assert!(crate::dirent::layout::is_used(&area, 0));
    assert!(crate::dirent::layout::is_used(&area, 1));
    assert!(!crate::dirent::layout::is_used(&area, 2));
}

#[test]
fn a_placed_long_name_zeroes_its_continuation_record() {
    // Leaving whatever a deleted entry put there makes a slot-by-slot walker
    // report a name nobody created.
    let l = block_layout();
    let mut area = vec![0u8; BLKSIZE];
    let cont = l.dentry_off(1);
    area[cont..cont + SIZE_OF_DIR_ENTRY].fill(0xEE);
    place_entry(&mut area, &l, 0, b"123456789", 7, FT_REG_FILE);
    assert_eq!(&area[cont..cont + SIZE_OF_DIR_ENTRY], &vec![0u8; SIZE_OF_DIR_ENTRY][..]);
}

#[test]
fn two_entries_placed_in_order_both_read_back() {
    let l = block_layout();
    let mut area = vec![0u8; BLKSIZE];
    place_entry(&mut area, &l, 0, b"aaaaaaaaa", 1, FT_REG_FILE);
    let next = room_for(&area, &l, 1).unwrap();
    assert_eq!(next, 2);
    place_entry(&mut area, &l, next, b"b", 2, FT_DIR);
    let out = deblock::entries(&area, &l).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[1].name, b"b");
    assert_eq!(out[1].file_type, FT_DIR);
}

#[test]
fn clearing_an_entry_frees_every_slot_it_held() {
    let l = block_layout();
    let mut area = vec![0u8; BLKSIZE];
    place_entry(&mut area, &l, 0, b"123456789", 7, FT_REG_FILE);
    assert_eq!(clear_entry(&mut area, &l, 0), Some(7));
    assert!(!crate::dirent::layout::is_used(&area, 0));
    assert!(!crate::dirent::layout::is_used(&area, 1));
    assert!(deblock::entries(&area, &l).unwrap().is_empty());
}

#[test]
fn clearing_one_entry_leaves_its_neighbour() {
    let l = block_layout();
    let mut area = dentry_area(&l, &[ent("a", 1, FT_REG_FILE), ent("b", 2, FT_REG_FILE)]);
    clear_entry(&mut area, &l, 0);
    let out = deblock::entries(&area, &l).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, b"b");
}

#[test]
fn an_area_is_empty_only_when_no_slot_is_used() {
    let l = block_layout();
    let mut area = vec![0u8; BLKSIZE];
    assert!(area_is_empty(&area, &l));
    place_entry(&mut area, &l, 5, b"x", 1, FT_REG_FILE);
    assert!(!area_is_empty(&area, &l));
    clear_entry(&mut area, &l, 5);
    assert!(area_is_empty(&area, &l));
}

#[test]
fn a_cleared_slot_is_offered_again() {
    let l = block_layout();
    let mut area = vec![0u8; BLKSIZE];
    place_entry(&mut area, &l, 0, b"gone", 1, FT_REG_FILE);
    clear_entry(&mut area, &l, 0);
    assert_eq!(room_for(&area, &l, 1), Some(0));
}

#[test]
fn an_inline_areas_own_layout_is_used_for_placement() {
    let l = Layout::inline(3452);
    let mut area = vec![0u8; 3452];
    place_entry(&mut area, &l, 0, b"inline", 9, FT_REG_FILE);
    let out = deblock::entries(&area, &l).unwrap();
    assert_eq!(out[0].name, b"inline");
    // The same bytes under a block's layout do not decode to it.
    let mut padded = area.clone();
    padded.resize(BLKSIZE, 0);
    let wrong: Vec<Vec<u8>> = deblock::entries(&padded, &Layout::block())
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(!wrong.contains(&b"inline".to_vec()));
}

#[test]
fn a_full_inline_area_offers_nothing_and_forces_a_conversion() {
    let l = Layout::inline(40);
    let mut area = vec![0u8; 40];
    place_entry(&mut area, &l, 0, b".", 1, FT_DIR);
    place_entry(&mut area, &l, 1, b"..", 1, FT_DIR);
    assert_eq!(l.max, 2);
    assert_eq!(room_for(&area, &l, 1), None);
}
