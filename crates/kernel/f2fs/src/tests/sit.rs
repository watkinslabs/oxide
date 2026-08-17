//! The segment table: locating an entry and reading what is live.

use super::*;
use crate::summary::SitEntry;
use crate::test_image::meta::{put16, put64};
use alloc::vec;
use alloc::vec::Vec;

const SIT_BASE: u32 = 1026;
const SIT_BLOCKS: u32 = 512;

/// A segment entry with `live` blocks marked from the start.
fn entry(live: u16, seg_type: u16) -> SitEntry {
    let mut valid_map = [0u8; SIT_VBLOCK_MAP_SIZE];
    for i in 0..live as usize { valid_map[i / 8] |= 1 << (i % 8); }
    SitEntry { vblocks: (seg_type << SIT_VBLOCKS_SHIFT) | live, valid_map, mtime: 0 }
}

#[test]
fn a_segments_place_in_the_table_is_its_block_and_its_slot() {
    assert_eq!(locate(0), (0, 0));
    assert_eq!(locate(1), (0, SIT_ENTRY_SIZE));
    let per = SIT_ENTRY_PER_BLOCK as u32;
    assert_eq!(locate(per - 1), (0, (SIT_ENTRY_PER_BLOCK - 1) * SIT_ENTRY_SIZE));
    assert_eq!(locate(per), (1, 0));
}

#[test]
fn the_last_slot_of_a_table_block_stays_inside_it() {
    let (_, off) = locate(SIT_ENTRY_PER_BLOCK as u32 - 1);
    assert!(off + SIT_ENTRY_SIZE <= BLKSIZE);
}

#[test]
fn the_table_holds_half_its_area() {
    assert_eq!(area_blocks(2, BLKS_PER_SEG), BLKS_PER_SEG);
    assert_eq!(area_blocks(4, BLKS_PER_SEG), 2 * BLKS_PER_SEG);
}

#[test]
fn the_first_copy_is_the_area_start_when_the_bit_is_clear() {
    assert_eq!(block_addr(SIT_BASE, SIT_BLOCKS, 0, &[0u8; 64]), SIT_BASE);
}

#[test]
fn a_set_bit_selects_the_copy_a_whole_half_area_on() {
    // This is NOT the node table's interleave: the second copy sits after all
    // of the first, so applying one rule to both reads the wrong block.
    assert_eq!(block_addr(SIT_BASE, SIT_BLOCKS, 0, &[1u8]), SIT_BASE + SIT_BLOCKS);
}

#[test]
fn table_blocks_are_consecutive() {
    let per = SIT_ENTRY_PER_BLOCK as u32;
    assert_eq!(block_addr(SIT_BASE, SIT_BLOCKS, per, &[0u8; 64]), SIT_BASE + 1);
    assert_eq!(block_addr(SIT_BASE, SIT_BLOCKS, per * 2, &[0u8; 64]), SIT_BASE + 2);
}

#[test]
fn the_selecting_bit_is_indexed_by_table_block() {
    let mut bitmap = [0u8; 64];
    bitmap[0] = 0b0000_0010;
    let per = SIT_ENTRY_PER_BLOCK as u32;
    assert_eq!(block_addr(SIT_BASE, SIT_BLOCKS, 0, &bitmap), SIT_BASE);
    assert_eq!(block_addr(SIT_BASE, SIT_BLOCKS, per, &bitmap), SIT_BASE + 1 + SIT_BLOCKS);
}

/// A table block holding `entries` at their own slots.
fn table_block(entries: &[(u32, u16)]) -> Vec<u8> {
    let mut b = vec![0u8; BLKSIZE];
    for (segno, live) in entries {
        let (_, off) = locate(*segno);
        put16(&mut b, off + SIT_VBLOCKS, *live);
        for i in 0..*live as usize { b[off + SIT_VALID_MAP + i / 8] |= 1 << (i % 8); }
        put64(&mut b, off + SIT_MTIME, 42);
    }
    b
}

#[test]
fn the_table_answers_when_the_journal_has_nothing() {
    let block = table_block(&[(3, 17)]);
    assert_eq!(resolve(&Vec::new(), &block, 3).unwrap().valid_blocks(), 17);
}

#[test]
fn a_journalled_entry_overrides_the_table() {
    let block = table_block(&[(3, 17)]);
    let journal = vec![(3u32, entry(200, 0))];
    assert_eq!(resolve(&journal, &block, 3).unwrap().valid_blocks(), 200);
}

#[test]
fn a_journal_entry_for_another_segment_does_not_override() {
    let block = table_block(&[(3, 17)]);
    let journal = vec![(4u32, entry(200, 0))];
    assert_eq!(resolve(&journal, &block, 3).unwrap().valid_blocks(), 17);
}

#[test]
fn journalled_reports_only_an_exact_match() {
    let journal = vec![(1u32, entry(1, 0)), (2u32, entry(2, 0))];
    assert_eq!(journalled(&journal, 2).unwrap().valid_blocks(), 2);
    assert!(journalled(&journal, 3).is_none());
}

#[test]
fn an_entry_whose_count_matches_its_map_is_consistent() {
    assert!(self_consistent(&entry(9, 1), BLKS_PER_SEG));
    assert!(self_consistent(&entry(0, 0), BLKS_PER_SEG));
    assert!(self_consistent(&entry(BLKS_PER_SEG as u16, 0), BLKS_PER_SEG));
}

#[test]
fn an_entry_whose_count_disagrees_with_its_map_is_not() {
    let mut e = entry(9, 0);
    e.vblocks = 10;
    assert!(!self_consistent(&e, BLKS_PER_SEG));
}

#[test]
fn an_entry_claiming_more_blocks_than_a_segment_holds_is_not() {
    let mut e = entry(0, 0);
    e.vblocks = BLKS_PER_SEG as u16 + 1;
    assert!(!self_consistent(&e, BLKS_PER_SEG));
}

#[test]
fn the_type_field_does_not_leak_into_the_count() {
    // A high type with a zero count must still read as consistent.
    assert!(self_consistent(&entry(0, 5), BLKS_PER_SEG));
}
