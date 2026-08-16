//! The per-block free map: what it remembers, and what it refuses to guess.

use super::*;
use crate::uapi::NAT_ENTRY_PER_BLOCK;

/// The first id of the second table block, used wherever a test needs an id
/// that is not in block zero. # C: O(1)
fn second_block() -> u32 { NAT_ENTRY_PER_BLOCK as u32 }

#[test]
fn an_unscanned_block_records_nothing_rather_than_guessing() {
    let mut b = Bitmaps::new();
    b.update(7, true, false);
    assert!(!b.is_free(7));
    assert_eq!(b.free_count(0), 0);
    assert_eq!(b.scanned_blocks(), 0);
}

#[test]
fn a_scanned_block_remembers_what_it_was_told() {
    let mut b = Bitmaps::new();
    b.mark_scanned(0);
    b.update(7, true, false);
    b.update(9, true, false);
    assert!(b.is_free(7) && b.is_free(9) && !b.is_free(8));
    assert_eq!(b.free_count(0), 2);
    assert_eq!(b.free_in_block(0), alloc::vec![7, 9]);
}

#[test]
fn setting_the_same_id_twice_counts_it_once() {
    let mut b = Bitmaps::new();
    b.mark_scanned(0);
    b.update(7, true, false);
    b.update(7, true, false);
    assert_eq!(b.free_count(0), 1);
}

#[test]
fn clearing_an_id_that_was_never_free_leaves_the_count_alone() {
    let mut b = Bitmaps::new();
    b.mark_scanned(0);
    b.update(7, true, false);
    b.update(8, false, false);
    assert_eq!(b.free_count(0), 1);
}

#[test]
fn a_clear_while_folding_a_block_in_does_not_lower_the_count() {
    // The scan establishes the count as it goes; an entry it finds in use was
    // never counted, so lowering the count for it would drive it negative.
    let mut b = Bitmaps::new();
    b.mark_scanned(0);
    b.update(7, true, true);
    b.update(7, false, true);
    assert_eq!(b.free_count(0), 1);
    assert!(!b.is_free(7));
}

#[test]
fn a_clear_outside_a_scan_lowers_the_count() {
    let mut b = Bitmaps::new();
    b.mark_scanned(0);
    b.update(7, true, false);
    b.update(7, false, false);
    assert_eq!(b.free_count(0), 0);
}

#[test]
fn each_block_keeps_its_own_map_and_count() {
    let mut b = Bitmaps::new();
    b.mark_scanned(0);
    b.mark_scanned(1);
    b.update(3, true, false);
    b.update(second_block() + 3, true, false);
    b.update(second_block() + 4, true, false);
    assert_eq!((b.free_count(0), b.free_count(1)), (1, 2));
    assert_eq!(b.free_in_block(1), alloc::vec![second_block() + 3, second_block() + 4]);
}

#[test]
fn only_blocks_holding_something_free_are_offered_for_a_rewalk() {
    let mut b = Bitmaps::new();
    for ofs in 0..3 { b.mark_scanned(ofs); }
    b.update(second_block() + 1, true, false);
    assert_eq!(b.blocks_with_free(), alloc::vec![1]);
}

#[test]
fn marking_a_block_scanned_twice_keeps_what_it_already_held() {
    let mut b = Bitmaps::new();
    b.mark_scanned(0);
    b.update(5, true, false);
    b.mark_scanned(0);
    assert!(b.is_free(5));
    assert_eq!(b.free_count(0), 1);
}

#[test]
fn the_last_id_of_a_block_is_addressable_and_the_next_one_is_not_its_business() {
    let mut b = Bitmaps::new();
    b.mark_scanned(0);
    let last = second_block() - 1;
    b.update(last, true, false);
    assert!(b.is_free(last));
    assert_eq!(b.free_in_block(0), alloc::vec![last]);
    assert!(!b.is_free(second_block()));
}

#[test]
fn the_footprint_follows_the_blocks_that_have_been_read() {
    let mut b = Bitmaps::new();
    assert_eq!(b.mem_bytes(), 0);
    b.mark_scanned(0);
    let one = b.mem_bytes();
    assert!(one > 0);
    b.mark_scanned(4);
    assert_eq!(b.mem_bytes(), one * 2);
}
