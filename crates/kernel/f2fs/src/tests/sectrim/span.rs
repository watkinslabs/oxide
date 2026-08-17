//! Which bytes a secure-trim request names.

use super::*;
use syscall::errno::Errno;

const BLK: u64 = crate::uapi::BLKSIZE as u64;
const MAX: u64 = 1 << 40;

#[test]
fn a_whole_block_range_inside_the_file() {
    let s = span(8 * BLK, BLK, 2 * BLK, MAX).unwrap().unwrap();
    assert_eq!(s, Span { first: 1, end: 3 });
}

#[test]
fn a_start_at_or_past_the_end_is_refused() {
    assert_eq!(span(BLK, BLK, BLK, MAX), Err(Errno::Einval));
    assert_eq!(span(BLK, 2 * BLK, BLK, MAX), Err(Errno::Einval));
}

#[test]
fn a_length_of_zero_names_nothing_and_succeeds() {
    assert_eq!(span(8 * BLK, 0, 0, MAX), Ok(None));
}

#[test]
fn an_unaligned_start_is_refused() {
    assert_eq!(span(8 * BLK, 1, BLK, MAX), Err(Errno::Einval));
}

#[test]
fn an_unaligned_end_short_of_the_file_is_refused() {
    // The block the range stops inside holds bytes the caller wants to keep.
    assert_eq!(span(8 * BLK, 0, BLK + 1, MAX), Err(Errno::Einval));
}

#[test]
fn an_unaligned_end_at_the_end_of_the_file_is_allowed() {
    // The file itself ends mid-block, so erasing that block whole destroys
    // only bytes past the length.
    let s = span(2 * BLK + 7, BLK, 4 * BLK, MAX).unwrap().unwrap();
    assert_eq!(s, Span { first: 1, end: 3 });
}

#[test]
fn a_length_that_exactly_reaches_the_end_is_the_to_end_case() {
    // size - start == len, so the range runs to the end and the end need not
    // be aligned — which it is here anyway, so the answer is the same either
    // way and the test pins the boundary rather than the branch.
    let s = span(4 * BLK, BLK, 3 * BLK, MAX).unwrap().unwrap();
    assert_eq!(s, Span { first: 1, end: 4 });
}

#[test]
fn the_everything_length_is_bounded_by_what_the_volume_can_hold() {
    let s = span(BLK + 1, 0, u64::MAX, 16 * BLK).unwrap().unwrap();
    assert_eq!(s, Span { first: 0, end: 16 });
}
