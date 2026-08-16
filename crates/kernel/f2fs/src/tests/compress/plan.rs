//! What a rewritten cluster's slots become, and the two block counts.

use alloc::vec;

use crate::compress::plan::{
    cluster_blocks, compr_blocks_after, compressed, compressed_extent, may_compress, plain, Slot,
};
use crate::uapi::{BLKSIZE, COMPRESS_ADDR, NEW_ADDR, NULL_ADDR};

#[test]
fn a_compressed_cluster_is_a_sentinel_then_the_image_then_reservations() {
    assert_eq!(
        compressed(4, 1),
        vec![Slot::Sentinel, Slot::Data(0), Slot::Reserved, Slot::Reserved]
    );
    assert_eq!(
        compressed(4, 3),
        vec![Slot::Sentinel, Slot::Data(0), Slot::Data(1), Slot::Data(2)]
    );
}

#[test]
fn the_slots_past_the_image_are_reserved_and_not_cleared() {
    // Cleared, they would hand the space back silently and leave the recorded
    // saving describing blocks that are already gone.
    for blocks in 1..8usize {
        let slots = compressed(8, blocks);
        assert!(slots.iter().all(|s| s.owned()), "image of {blocks}");
        assert_eq!(slots.iter().filter(|s| **s == Slot::Reserved).count(), 7 - blocks);
    }
}

#[test]
fn a_plain_cluster_keeps_its_holes() {
    assert_eq!(
        plain(&[true, false, true, false]),
        vec![Slot::Data(0), Slot::Hole, Slot::Data(2), Slot::Hole]
    );
    assert!(!Slot::Hole.owned());
}

#[test]
fn a_cluster_is_compressed_only_when_its_addresses_open_with_the_sentinel() {
    assert_eq!(compressed_extent(&[COMPRESS_ADDR, 100, 101, NEW_ADDR]), Some(3));
    assert_eq!(compressed_extent(&[COMPRESS_ADDR, NEW_ADDR, NEW_ADDR, NEW_ADDR]), Some(1));
    assert_eq!(compressed_extent(&[COMPRESS_ADDR, NULL_ADDR, NULL_ADDR, NULL_ADDR]), Some(1));
    assert_eq!(compressed_extent(&[100, 101, 102, 103]), None);
    assert_eq!(compressed_extent(&[NULL_ADDR; 4]), None);
    assert_eq!(compressed_extent(&[]), None);
}

#[test]
fn every_slot_that_is_not_empty_counts_against_the_file() {
    assert_eq!(cluster_blocks(&[COMPRESS_ADDR, 100, NEW_ADDR, NEW_ADDR]), 4);
    assert_eq!(cluster_blocks(&[COMPRESS_ADDR, 100, NULL_ADDR, NULL_ADDR]), 2);
    assert_eq!(cluster_blocks(&[100, 101, 102, 103]), 4);
    assert_eq!(cluster_blocks(&[NULL_ADDR; 4]), 0);
}

#[test]
fn compressing_a_cluster_records_the_blocks_it_did_not_need() {
    // Four blocks stored in one image block: three saved, and the sentinel is
    // not one of them.
    assert_eq!(compr_blocks_after(0, 4, None, Some(2)), 3);
    assert_eq!(compr_blocks_after(0, 8, None, Some(2)), 7);
    assert_eq!(compr_blocks_after(0, 8, None, Some(8)), 1);
}

#[test]
fn rewriting_a_compressed_cluster_replaces_its_saving_rather_than_adding_to_it() {
    // Was one image block of four, now three: the file saved three and now
    // saves one.
    assert_eq!(compr_blocks_after(3, 4, Some(2), Some(4)), 1);
    // And the other way round.
    assert_eq!(compr_blocks_after(1, 4, Some(4), Some(2)), 3);
}

#[test]
fn overwriting_a_compressed_cluster_with_plain_blocks_gives_the_saving_back() {
    assert_eq!(compr_blocks_after(3, 4, Some(2), None), 0);
    assert_eq!(compr_blocks_after(6, 4, Some(2), None), 3);
}

#[test]
fn a_file_whose_saving_was_already_released_is_not_charged_for_it_twice() {
    // Nothing recorded means the blocks are already gone; subtracting anyway
    // would drive the count below zero and make the inode inconsistent.
    assert_eq!(compr_blocks_after(0, 4, Some(2), None), 0);
    assert_eq!(compr_blocks_after(0, 4, Some(2), Some(2)), 3);
}

#[test]
fn a_plain_cluster_rewritten_plain_changes_nothing() {
    for cur in [0u64, 5, 100] {
        assert_eq!(compr_blocks_after(cur, 4, None, None), cur);
    }
}

#[test]
fn only_a_cluster_the_file_covers_whole_may_be_compressed() {
    // Four blocks per cluster; the file is five blocks and a hundred bytes,
    // so it reaches into the second cluster but not through it.
    let size = 5 * BLKSIZE as u64 + 100;
    assert!(may_compress(0, 4, size, BLKSIZE));
    assert!(!may_compress(4, 4, size, BLKSIZE));
    // A file that stops exactly at a cluster boundary covers that cluster.
    assert!(may_compress(4, 4, 8 * BLKSIZE as u64, BLKSIZE));
    assert!(!may_compress(4, 4, 7 * BLKSIZE as u64 - 1, BLKSIZE));
    // The last partial block still counts as covered, which is the rule the
    // reference applies: pages, not bytes.
    assert!(may_compress(4, 4, 7 * BLKSIZE as u64 + 1, BLKSIZE));
    assert!(!may_compress(0, 4, 1, BLKSIZE));
}
