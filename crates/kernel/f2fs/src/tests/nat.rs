//! Turning a node id into the block its node lives at.

use super::*;
use crate::summary::NatEntry;
use crate::test_image::meta::put32;
use alloc::vec;
use alloc::vec::Vec;

const NAT_BASE: u32 = 2050;

#[test]
fn a_node_ids_place_in_the_table_is_its_block_and_its_slot() {
    assert_eq!(locate(0), (0, 0));
    assert_eq!(locate(1), (0, NAT_ENTRY_SIZE));
    assert_eq!(locate(NAT_ENTRY_PER_BLOCK as u32 - 1), (0, (NAT_ENTRY_PER_BLOCK - 1) * NAT_ENTRY_SIZE));
    assert_eq!(locate(NAT_ENTRY_PER_BLOCK as u32), (1, 0));
}

#[test]
fn the_last_slot_of_a_block_stays_inside_it() {
    let (_, off) = locate(NAT_ENTRY_PER_BLOCK as u32 - 1);
    assert!(off + NAT_ENTRY_SIZE <= BLKSIZE);
}

#[test]
fn the_first_copy_is_the_area_start_when_the_bit_is_clear() {
    let bitmap = [0u8; 64];
    assert_eq!(block_addr(NAT_BASE, BLKS_PER_SEG, 0, &bitmap), NAT_BASE);
}

#[test]
fn a_set_bit_selects_the_copy_one_segment_on() {
    let bitmap = [0b0000_0001u8; 1];
    assert_eq!(block_addr(NAT_BASE, BLKS_PER_SEG, 0, &bitmap), NAT_BASE + BLKS_PER_SEG);
}

#[test]
fn the_two_copies_interleave_segment_wise_not_block_wise() {
    // Inside a segment the offset is subtracted back out, so consecutive table
    // blocks are consecutive on the medium; a plain doubling would scatter
    // them and read the wrong block for every id past the first.
    let bitmap = [0u8; 64];
    let per = NAT_ENTRY_PER_BLOCK as u32;
    assert_eq!(block_addr(NAT_BASE, BLKS_PER_SEG, 0, &bitmap), NAT_BASE);
    assert_eq!(block_addr(NAT_BASE, BLKS_PER_SEG, per, &bitmap), NAT_BASE + 1);
    assert_eq!(block_addr(NAT_BASE, BLKS_PER_SEG, per * 2, &bitmap), NAT_BASE + 2);
}

#[test]
fn the_first_block_of_the_second_segment_jumps_a_whole_segment() {
    // Block offset 512 is the first of the next pair of segments: the doubling
    // shows up here rather than between neighbouring blocks.
    let bitmap = [0u8; 128];
    let per = NAT_ENTRY_PER_BLOCK as u32;
    let nid = per * BLKS_PER_SEG;
    assert_eq!(block_addr(NAT_BASE, BLKS_PER_SEG, nid, &bitmap), NAT_BASE + BLKS_PER_SEG * 2);
}

#[test]
fn the_bit_that_selects_a_copy_is_indexed_by_block_not_by_node_id() {
    // Bit one covers the SECOND table block, which is node id 455 onward.
    let mut bitmap = [0u8; 64];
    bitmap[0] = 0b0000_0010;
    let per = NAT_ENTRY_PER_BLOCK as u32;
    assert_eq!(block_addr(NAT_BASE, BLKS_PER_SEG, 1, &bitmap), NAT_BASE);
    assert_eq!(block_addr(NAT_BASE, BLKS_PER_SEG, per, &bitmap), NAT_BASE + 1 + BLKS_PER_SEG);
}

/// A table block whose slots hold `entries`.
fn table_block(entries: &[(u32, u32)]) -> Vec<u8> {
    let mut b = vec![0u8; BLKSIZE];
    for (nid, addr) in entries {
        let (_, off) = locate(*nid);
        put32(&mut b, off + NAT_INO, *nid);
        put32(&mut b, off + NAT_BLOCK_ADDR, *addr);
    }
    b
}

#[test]
fn the_table_answers_when_the_journal_has_nothing() {
    let block = table_block(&[(4, 5000)]);
    let e = resolve(&Vec::new(), &block, 4).unwrap();
    assert_eq!(e.block_addr, 5000);
}

#[test]
fn a_journalled_entry_overrides_the_table() {
    // This is the whole point of the journal: the table copy predates it by a
    // checkpoint, and taking the table's answer reads a stale node.
    let block = table_block(&[(4, 5000)]);
    let journal = vec![(4u32, NatEntry { version: 1, ino: 4, block_addr: 6000 })];
    assert_eq!(resolve(&journal, &block, 4).unwrap().block_addr, 6000);
}

#[test]
fn a_journal_entry_for_another_node_does_not_override() {
    let block = table_block(&[(4, 5000)]);
    let journal = vec![(9u32, NatEntry { version: 1, ino: 9, block_addr: 6000 })];
    assert_eq!(resolve(&journal, &block, 4).unwrap().block_addr, 5000);
}

#[test]
fn journalled_reports_only_an_exact_match() {
    let journal = vec![
        (4u32, NatEntry { version: 0, ino: 4, block_addr: 10 }),
        (5u32, NatEntry { version: 0, ino: 5, block_addr: 11 }),
    ];
    assert_eq!(journalled(&journal, 5).unwrap().block_addr, 11);
    assert_eq!(journalled(&journal, 6), None);
}

#[test]
fn a_journalled_deletion_overrides_a_live_table_entry() {
    // An entry journalled with a null address means the node is GONE; taking
    // the table's answer would hand out a freed block.
    let block = table_block(&[(4, 5000)]);
    let journal = vec![(4u32, NatEntry { version: 1, ino: 0, block_addr: NULL_ADDR })];
    assert_eq!(resolve(&journal, &block, 4).unwrap().block_addr, NULL_ADDR);
}

#[test]
fn node_id_zero_and_the_reserved_ones_are_out_of_range() {
    assert!(!nid_in_range(0, 1000));
    assert!(nid_in_range(1, 1000));
    assert!(nid_in_range(999, 1000));
    assert!(!nid_in_range(1000, 1000));
}

#[test]
fn the_table_holds_half_its_area_because_the_other_half_is_the_second_copy() {
    // Two segments of table hold one segment's worth of distinct blocks.
    assert_eq!(max_nid(2, BLKS_PER_SEG), BLKS_PER_SEG * NAT_ENTRY_PER_BLOCK as u32);
    assert_eq!(max_nid(4, BLKS_PER_SEG), 2 * BLKS_PER_SEG * NAT_ENTRY_PER_BLOCK as u32);
}

#[test]
fn an_odd_table_segment_count_rounds_down() {
    assert_eq!(max_nid(1, BLKS_PER_SEG), 0);
    assert_eq!(max_nid(3, BLKS_PER_SEG), BLKS_PER_SEG * NAT_ENTRY_PER_BLOCK as u32);
}
