//! Filling the cache from the three places that know which ids are free.

use super::*;
use alloc::vec;
use alloc::vec::Vec;
use crate::uapi::{BLKSIZE, RESERVED_NODE_NUM};
use crate::freenid::NidState;

/// Ids one table block covers. # C: O(1)
const PER: u32 = NAT_ENTRY_PER_BLOCK as u32;

/// A table block in which every entry is empty, then whatever `used` says.
/// # C: O(used)
fn block(used: &[(usize, u32)]) -> Vec<u8> {
    let mut b = vec![0u8; BLKSIZE];
    for &(i, addr) in used {
        let at = i * NAT_ENTRY_SIZE + crate::uapi::NAT_BLOCK_ADDR;
        b[at..at + 4].copy_from_slice(&addr.to_le_bytes());
    }
    b
}

/// A cache with the first `n` table blocks folded in, all of them empty.
/// # C: O(n * ids per block)
fn scanned(n: u32, max_nid: u32) -> FreeNids {
    let mut f = FreeNids::new(0, max_nid);
    let empty = block(&[]);
    for i in 0..n { f.scan_nat_block(&empty, i * PER, max_nid).unwrap(); }
    f
}

// ------------------------------------------------------------- a table block

#[test]
fn an_all_empty_table_block_makes_every_usable_id_in_it_free() {
    let f = scanned(1, PER);
    assert_eq!(f.free_count(), PER - RESERVED_NODE_NUM);
    assert!(f.block_scanned(0));
}

#[test]
fn a_block_with_addresses_records_those_ids_as_used() {
    let mut f = FreeNids::new(0, PER);
    f.scan_nat_block(&block(&[(5, 100), (9, 200)]), 0, PER).unwrap();
    assert_eq!(f.free_count(), PER - RESERVED_NODE_NUM - 2);
    assert_eq!(f.state_of(5), None);
    assert_eq!(f.state_of(9), None);
    assert_eq!(f.state_of(6), Some(NidState::Free));
}

#[test]
fn a_walk_that_starts_mid_block_leaves_the_earlier_ids_alone() {
    let mut f = FreeNids::new(0, PER);
    f.scan_nat_block(&block(&[]), 100, PER).unwrap();
    assert_eq!(f.free_count(), PER - 100);
    assert_eq!(f.state_of(99), None);
    assert_eq!(f.state_of(100), Some(NidState::Free));
}

#[test]
fn a_walk_stops_at_the_end_of_the_table() {
    let mut f = FreeNids::new(0, 10);
    f.scan_nat_block(&block(&[]), 0, 10).unwrap();
    assert_eq!(f.free_count(), 10 - RESERVED_NODE_NUM);
    assert_eq!(f.state_of(10), None);
}

#[test]
fn a_reserved_address_in_the_table_is_reported_as_damage() {
    let mut f = FreeNids::new(0, PER);
    let r = f.scan_nat_block(&block(&[(5, crate::uapi::NEW_ADDR)]), 0, PER);
    assert_eq!(r, Err(Corrupt::ReservedAddr));
    // What the walk had already established stands; the walk simply stops.
    assert_eq!(f.free_count(), 2);
}

#[test]
fn a_block_too_short_to_hold_its_entries_is_reported_as_damage() {
    let mut f = FreeNids::new(0, PER);
    assert_eq!(f.scan_nat_block(&[0u8; 10], 0, PER), Err(Corrupt::ShortBlock));
}

#[test]
fn a_second_walk_of_the_same_block_does_not_hold_its_ids_twice() {
    let mut f = scanned(1, PER);
    let before = f.free_count();
    f.scan_nat_block(&block(&[]), 0, PER).unwrap();
    assert_eq!(f.free_count(), before);
}

// ----------------------------------------------------------------- the journal

#[test]
fn a_journalled_empty_entry_frees_the_id() {
    let mut f = FreeNids::new(0, PER);
    f.scan_journal([(7u32, crate::uapi::NULL_ADDR)].into_iter(), PER);
    assert_eq!(f.state_of(7), Some(NidState::Free));
}

#[test]
fn a_journalled_address_takes_the_id_back_from_the_table() {
    let mut f = scanned(1, PER);
    assert_eq!(f.state_of(7), Some(NidState::Free));
    f.scan_journal([(7u32, 500u32)].into_iter(), PER);
    assert_eq!(f.state_of(7), None);
}

#[test]
fn the_journal_does_not_raise_what_the_volume_has_left() {
    let mut f = FreeNids::new(0, 10);
    f.scan_journal([(7u32, crate::uapi::NULL_ADDR)].into_iter(), PER);
    assert_eq!(f.available_nids(), 10);
}

// ------------------------------------------------------------- the free map

#[test]
fn a_rewalk_of_the_map_puts_back_what_the_list_forgot() {
    let mut f = scanned(1, PER);
    for nid in f.free_order() { f.remove(nid); }
    assert_eq!(f.free_count(), 0);
    f.scan_free_nid_bits(PER);
    assert_eq!(f.free_count(), PER - RESERVED_NODE_NUM);
}

#[test]
fn a_rewalk_does_not_put_back_an_id_the_table_showed_as_used() {
    let mut f = FreeNids::new(0, PER);
    f.scan_nat_block(&block(&[(5, 100)]), 0, PER).unwrap();
    for nid in f.free_order() { f.remove(nid); }
    f.scan_free_nid_bits(PER);
    assert_eq!(f.state_of(5), None);
    assert_eq!(f.free_count(), PER - RESERVED_NODE_NUM - 1);
}

#[test]
fn a_rewalk_stops_at_the_ceiling() {
    let blocks = MAX_FREE_NIDS / PER + 1;
    let max_nid = blocks * PER;
    let mut f = scanned(blocks, max_nid);
    assert!(f.free_count() > MAX_FREE_NIDS);
    for nid in f.free_order() { f.remove(nid); }
    f.scan_free_nid_bits(max_nid);
    assert_eq!(f.free_count(), MAX_FREE_NIDS);
}

#[test]
fn an_id_handed_out_is_not_put_back_by_a_rewalk() {
    let mut f = scanned(1, PER);
    let nid = f.alloc().unwrap();
    f.alloc_done(nid);
    f.scan_free_nid_bits(PER);
    assert_eq!(f.state_of(nid), None);
}

// ------------------------------------------------------------------- the plan

#[test]
fn the_plan_reads_the_blocks_the_cursor_points_at() {
    let f = FreeNids::new(0, PER * 20);
    let p = f.build_plan(PER * 20);
    assert_eq!(p.reads.len(), FREE_NID_PAGES as usize);
    assert_eq!(p.reads[0], 0);
    assert_eq!(p.reads[1], PER);
    assert_eq!(p.next, PER * FREE_NID_PAGES);
}

#[test]
fn the_plan_skips_a_block_already_read_but_still_moves_the_cursor() {
    let max_nid = PER * 20;
    let mut f = FreeNids::new(0, max_nid);
    f.scan_nat_block(&block(&[]), PER, max_nid).unwrap();
    let p = f.build_plan(max_nid);
    assert!(!p.reads.contains(&PER));
    assert_eq!(p.reads.len(), FREE_NID_PAGES as usize - 1);
    assert_eq!(p.next, PER * FREE_NID_PAGES);
}

#[test]
fn the_plan_wraps_at_the_end_of_the_table() {
    let max_nid = PER * 4;
    let mut f = FreeNids::new(0, max_nid);
    f.set_next_scan_nid(PER * 3);
    let p = f.build_plan(max_nid);
    // Four blocks, eight considered: the pass reads each once and stops
    // offering the ones it has already planned.
    assert_eq!(p.reads, vec![PER * 3, 0, PER, PER * 2]);
    assert_eq!(p.next, PER * 3);
}

#[test]
fn a_cursor_past_the_end_of_the_table_restarts_at_the_beginning() {
    let max_nid = PER * 4;
    let mut f = FreeNids::new(0, max_nid);
    f.set_next_scan_nid(max_nid + 1);
    assert_eq!(f.build_plan(max_nid).reads[0], 0);
}

#[test]
fn a_cursor_left_mid_block_is_aligned_down_before_the_walk() {
    let max_nid = PER * 4;
    let mut f = FreeNids::new(0, max_nid);
    f.set_next_scan_nid(PER + 7);
    assert_eq!(f.build_plan(max_nid).reads[0], PER);
}
