// Provenance: CORB/RIRB pointer rules. Advancing the write pointer into the
// read pointer overwrites a command the controller has not consumed.

use super::*;

#[test]
fn the_corb_write_pointer_advances_and_wraps() {
    assert_eq!(corb_next_write(0, 0), Some(1));
    assert_eq!(corb_next_write(254, 0), Some(255));
    assert_eq!(corb_next_write(255, 1), Some(0));
}

#[test]
fn a_full_corb_refuses_the_next_entry() {
    // Write one behind read: advancing would land on the unread entry.
    assert_eq!(corb_next_write(5, 6), None);
    assert_eq!(corb_next_write(255, 0), None);
}

#[test]
fn an_invalid_pointer_is_not_treated_as_a_position() {
    assert_eq!(corb_next_write(POINTER_INVALID, 0), None);
    assert_eq!(corb_next_write(0, POINTER_INVALID), None);
    assert_eq!(rirb_pending(0, POINTER_INVALID), 0);
}

#[test]
fn rirb_pending_counts_entries_across_the_wrap() {
    assert_eq!(rirb_pending(0, 0), 0);
    assert_eq!(rirb_pending(0, 3), 3);
    assert_eq!(rirb_pending(254, 1), 3);
}

#[test]
fn stepping_the_rirb_gives_the_dword_index_of_the_new_entry() {
    assert_eq!(rirb_step(0), (1, 2));
    assert_eq!(rirb_step(255), (0, 0));
    assert_eq!(corb_offset(3), 12);
}
