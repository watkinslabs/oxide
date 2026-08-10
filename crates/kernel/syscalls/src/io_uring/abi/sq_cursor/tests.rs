use super::*;

const REWIND: u32 = IORING_SETUP_SQ_REWIND;

#[test]
fn an_ordinary_ring_starts_where_it_left_off_and_says_so() {
    assert!(!rewinds(0));
    assert!(publishes_head(0));
    assert_eq!(batch_start(0, 13), 13);
}

#[test]
fn a_rewinding_ring_starts_at_slot_zero_every_pass_and_stays_quiet() {
    assert!(rewinds(REWIND));
    assert!(!publishes_head(REWIND),
            "publishing the head would make the next pass start elsewhere");
    for head in [0u32, 1, 7, u32::MAX] { assert_eq!(batch_start(REWIND, head), 0); }
}

/// An ordinary ring takes what userspace published and no more, however much
/// the caller claims to have submitted.
#[test]
fn an_ordinary_batch_is_bounded_by_the_published_tail() {
    assert_eq!(batch_len(0, 100, 5, 0, 8), 5);
    assert_eq!(batch_len(0, 3, 5, 0, 8), 3);
    assert_eq!(batch_len(0, 100, 0, 0, 8), 0, "an empty ring submits nothing");
}

/// The counters are free-running, so a tail that has wrapped past `u32::MAX`
/// still yields the right count.
#[test]
fn an_ordinary_batch_survives_the_counter_wrapping() {
    assert_eq!(batch_len(0, 100, 3, u32::MAX - 1, 8), 5);
}

/// A rewinding ring's tail never moves, so bounding by it would submit
/// nothing, ever. It is bounded by the array and by the caller's own count.
#[test]
fn a_rewinding_batch_is_bounded_by_the_array_and_the_callers_count() {
    // Tail and head both zero — an ordinary ring would take nothing here.
    assert_eq!(batch_len(0, 4, 0, 0, 8), 0);
    assert_eq!(batch_len(REWIND, 4, 0, 0, 8), 4);
    // And never past the array, however much the caller claims.
    assert_eq!(batch_len(REWIND, 100, 0, 0, 8), 8);
    assert_eq!(batch_len(REWIND, 0, 0, 0, 8), 0);
}

/// A rewinding pass re-reads the same slots every time: two identical calls
/// take the same entries, which is the whole behaviour the flag names.
#[test]
fn two_rewinding_passes_read_the_same_slots() {
    let (tail, entries) = (0u32, 8u32);
    // The head the kernel would have reached last pass, had it published one.
    for head in [0u32, 4, 8] {
        assert_eq!(batch_start(REWIND, head), 0);
        assert_eq!(batch_len(REWIND, 4, tail, head, entries), 4);
    }
}
