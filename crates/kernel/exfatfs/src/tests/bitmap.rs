use super::*;
use crate::uapi::FIRST_CLUSTER;

/// A bitmap over 64 data clusters, all free.
fn empty() -> Bitmap { Bitmap::new(alloc::vec![0u8; 8], 64) }

#[test]
fn bit_zero_is_cluster_two() {
    let mut b = empty();
    b.set(FIRST_CLUSTER).unwrap();
    assert_eq!(b.bytes()[0], 0b0000_0001);
    assert!(b.is_set(2));
    assert!(!b.is_set(3));
}

#[test]
fn the_eighth_data_cluster_starts_the_second_byte() {
    let mut b = empty();
    b.set(10).unwrap();
    assert_eq!(b.bytes()[1], 0b0000_0001);
}

#[test]
fn a_cluster_the_bitmap_does_not_cover_reads_as_allocated() {
    // Reading an uncovered cluster as free would hand out a cluster nothing
    // can record.
    let mut b = empty();
    assert!(b.is_set(0));
    assert!(b.is_set(1));
    assert!(b.is_set(66));
    assert!(b.set(66).is_err());
    assert!(b.clear(66).is_err());
}

#[test]
fn a_bit_can_be_released() {
    let mut b = empty();
    b.set(5).unwrap();
    b.clear(5).unwrap();
    assert!(!b.is_set(5));
}

#[test]
fn the_free_search_starts_where_it_is_told() {
    let mut b = empty();
    for c in 2..10 { b.set(c).unwrap(); }
    assert_eq!(b.find_free(2), Some(10));
    assert_eq!(b.find_free(20), Some(20));
}

#[test]
fn the_free_search_wraps_once_to_the_front() {
    // Without the wrap, a delete near the front is never reused until the
    // next mount resets the hint.
    let mut b = empty();
    for c in 10..66 { b.set(c).unwrap(); }
    assert_eq!(b.find_free(20), Some(2));
}

#[test]
fn a_full_bitmap_finds_nothing() {
    let mut b = empty();
    for c in 2..66 { b.set(c).unwrap(); }
    assert_eq!(b.find_free(2), None);
    assert_eq!(b.used(), 64);
}

#[test]
fn padding_bits_past_the_cluster_count_are_never_handed_out() {
    // Eight bytes hold 64 bits; a volume with 60 data clusters leaves four
    // that name nothing.
    let b = Bitmap::new(alloc::vec![0u8; 8], 60);
    assert_eq!(b.find_free(2), Some(2));
    for c in 62..66 { assert!(b.is_set(c), "cluster {c} is past the count"); }
}

#[test]
fn a_run_is_reported_allocated_only_when_all_of_it_is() {
    let mut b = empty();
    for c in 5..9 { b.set(c).unwrap(); }
    assert!(b.range_set(5, 4));
    assert!(!b.range_set(5, 5));
}

#[test]
fn the_used_count_matches_the_bits() {
    let mut b = empty();
    assert_eq!(b.used(), 0);
    b.set(3).unwrap();
    b.set(40).unwrap();
    assert_eq!(b.used(), 2);
}

#[test]
fn a_bitmap_is_sized_from_the_cluster_count() {
    assert_eq!(bytes_for(0), 0);
    assert_eq!(bytes_for(1), 1);
    assert_eq!(bytes_for(8), 1);
    assert_eq!(bytes_for(9), 2);
}

#[test]
fn a_bit_is_located_in_its_own_sector_for_writeback() {
    let b = Bitmap::new(alloc::vec![0u8; 1024], 8192);
    // 512-byte sectors hold 4096 bits each.
    assert_eq!(b.sector_index(2, 9), Some(0));
    assert_eq!(b.sector_index(4097, 9), Some(0));
    assert_eq!(b.sector_index(4098, 9), Some(1));
    assert_eq!(b.sector_bytes(1, 512).unwrap().len(), 512);
}
