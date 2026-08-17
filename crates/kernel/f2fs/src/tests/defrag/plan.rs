//! The fragmentation rule and the refusal order, over stated facts.

use super::*;
use syscall::errno::Errno;

fn ok() -> Facts { Facts::default() }

// ------------------------------------------------------------------ refusals

#[test]
fn a_plain_file_is_admitted() {
    assert_eq!(admit(&ok()), Ok(()));
}

#[test]
fn a_released_compressed_file_is_refused() {
    assert_eq!(admit(&Facts { compress_released: true, ..ok() }), Err(Errno::Einval));
}

#[test]
fn a_file_in_an_atomic_span_is_refused() {
    assert_eq!(admit(&Facts { atomic: true, ..ok() }), Err(Errno::Einval));
}

#[test]
fn a_pinned_file_is_refused_because_its_blocks_may_not_move() {
    assert_eq!(admit(&Facts { pinned: true, ..ok() }), Err(Errno::Einval));
}

#[test]
fn a_mount_that_updates_in_place_is_refused_rather_than_reporting_a_move() {
    assert_eq!(admit(&Facts { inplace_update: true, ..ok() }), Err(Errno::Einval));
}

// -------------------------------------------------------------- fragmentation

#[test]
fn one_block_is_never_fragmented() {
    let mut s = Survey::new();
    s.note(100);
    assert!(!s.fragmented);
    assert_eq!(s.total, 1);
}

#[test]
fn a_contiguous_run_is_not_fragmented() {
    let mut s = Survey::new();
    for a in 100..110 { s.note(a); }
    assert!(!s.fragmented);
    assert_eq!(s.total, 10);
}

#[test]
fn a_gap_in_the_addresses_is_fragmentation() {
    let mut s = Survey::new();
    s.note(100);
    s.note(102);
    assert!(s.fragmented);
    assert_eq!(s.total, 2);
}

#[test]
fn going_backwards_is_fragmentation_too() {
    let mut s = Survey::new();
    s.note(100);
    s.note(99);
    assert!(s.fragmented);
}

#[test]
fn a_hole_between_two_adjacent_blocks_is_not_fragmentation() {
    // A sparse file laid out perfectly: the blocks that exist are next to
    // each other, and the logical gap costs nothing because nothing is read
    // from it. Resetting the run at a hole would rewrite this file forever.
    let mut s = Survey::new();
    s.note(100);
    // index 1 is a hole and is simply not fed.
    s.note(101);
    assert!(!s.fragmented);
    assert_eq!(s.total, 2);
}

#[test]
fn nothing_surveyed_is_not_fragmented() {
    assert!(!Survey::new().fragmented);
    assert_eq!(Survey::new().total, 0);
}

// -------------------------------------------------------------------- the cost

#[test]
fn the_section_count_rounds_up() {
    let mut s = Survey::new();
    for a in 100..(100 + 513) { s.note(a); }
    assert_eq!(s.sections_needed(512), 2);
}

#[test]
fn nothing_to_move_needs_no_section() {
    assert_eq!(Survey::new().sections_needed(512), 0);
}

// ------------------------------------------------------------ the cheap answer

#[test]
fn an_extent_spanning_the_range_ends_it_early() {
    assert!(extent_covers(Some((0, 100, 8)), 0, 8));
    assert!(extent_covers(Some((0, 100, 8)), 2, 6));
}

#[test]
fn an_extent_that_stops_short_does_not() {
    assert!(!extent_covers(Some((0, 100, 8)), 0, 9));
}

#[test]
fn an_extent_starting_late_does_not() {
    assert!(!extent_covers(Some((4, 100, 8)), 0, 8));
}

#[test]
fn no_extent_and_an_empty_one_answer_nothing() {
    assert!(!extent_covers(None, 0, 1));
    assert!(!extent_covers(Some((0, 100, 0)), 0, 1));
}
