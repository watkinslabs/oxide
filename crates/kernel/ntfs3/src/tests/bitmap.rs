use super::*;

fn empty() -> Bitmap { Bitmap::new(alloc::vec![0u8; 8], 64) }

#[test]
fn a_bit_round_trips() {
    let mut b = empty();
    b.set(5).unwrap();
    assert!(b.is_set(5));
    assert_eq!(b.bytes()[0], 0b0010_0000);
    b.clear(5).unwrap();
    assert!(!b.is_set(5));
}

#[test]
fn an_index_the_bitmap_does_not_cover_reads_as_in_use() {
    let mut b = empty();
    assert!(b.is_set(64));
    assert!(b.set(64).is_err());
    assert!(b.clear(64).is_err());
}

#[test]
fn padding_bits_past_the_count_are_never_handed_out() {
    // Eight bytes hold 64 bits; a volume with 60 leaves four that name
    // nothing.
    let b = Bitmap::new(alloc::vec![0u8; 8], 60);
    for i in 60..64 { assert!(b.is_set(i), "bit {i} is past the count"); }
    assert_eq!(b.find_free(58), Some(58));
}

#[test]
fn the_free_search_wraps_once() {
    let mut b = empty();
    for i in 10..64 { b.set(i).unwrap(); }
    assert_eq!(b.find_free(20), Some(0));
}

#[test]
fn a_full_bitmap_finds_nothing() {
    let mut b = empty();
    for i in 0..64 { b.set(i).unwrap(); }
    assert_eq!(b.find_free(0), None);
    assert_eq!(b.find_free_run(0, 1), None);
    assert_eq!(b.used(), 64);
}

#[test]
fn a_run_search_finds_consecutive_indexes() {
    // A file laid down as one extent is one run rather than `count` of them.
    let mut b = empty();
    for i in [3u64, 4, 8, 20] { b.set(i).unwrap(); }
    // Bits 0..2 are free, then 3 and 4 are taken, so a run of three fits at
    // the front and a run of four does not until past bit 8.
    assert_eq!(b.find_free_run(0, 3), Some(0));
    assert_eq!(b.find_free_run(0, 4), Some(9));
    assert_eq!(b.find_free_run(5, 3), Some(5));
    assert_eq!(b.find_free_run(0, 100), None);
    assert_eq!(b.find_free_run(0, 0), None);
}

#[test]
fn a_run_search_wraps_once_too() {
    let mut b = empty();
    for i in 8..64 { b.set(i).unwrap(); }
    assert_eq!(b.find_free_run(30, 4), Some(0));
}

#[test]
fn a_range_is_claimed_and_released_whole() {
    let mut b = empty();
    b.set_range(10, 5).unwrap();
    assert_eq!(b.used(), 5);
    assert!(!b.range_free(10, 5));
    assert!(b.range_free(15, 5));
    b.clear_range(10, 5).unwrap();
    assert_eq!(b.used(), 0);
}

#[test]
fn a_bitmap_is_sized_from_its_bit_count() {
    assert_eq!(bytes_for(0), 0);
    assert_eq!(bytes_for(1), 1);
    assert_eq!(bytes_for(8), 1);
    assert_eq!(bytes_for(9), 2);
}
