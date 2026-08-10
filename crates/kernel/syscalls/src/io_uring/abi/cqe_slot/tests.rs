use super::*;

const MIXED: u32 = IORING_SETUP_CQE_MIXED;
const WIDE: u32 = IORING_SETUP_CQE32;

#[test]
fn only_a_mixed_ring_charges_two_slots_for_a_wide_completion() {
    assert_eq!(slots(0, false), 1);
    assert_eq!(slots(WIDE, true), 1, "a 32-byte array holds one per slot");
    assert_eq!(slots(MIXED, false), 1);
    assert_eq!(slots(MIXED, true), 2);
}

#[test]
fn only_a_mixed_ring_marks_a_wide_completion() {
    assert!(!marks_32(0));
    assert!(!marks_32(WIDE), "every completion on a 32-byte ring is 32 bytes");
    assert!(marks_32(MIXED));
}

#[test]
fn a_plain_ring_cannot_carry_a_wide_completion_at_all() {
    assert!(!posts_32(0));
    assert!(posts_32(WIDE));
    assert!(posts_32(MIXED));
}

/// The ordinary case on every ring shape: one slot at the masked tail.
#[test]
fn a_narrow_completion_lands_at_the_masked_tail() {
    for flags in [0, WIDE, MIXED] {
        let p = place(flags, 5, 0, 8, false).expect("room");
        assert_eq!(p, Placement { filler_at: None, at: 5, advance: 1 }, "flags {flags:#x}");
    }
    // And the tail wraps like any free-running counter.
    let p = place(0, 8, 4, 8, false).expect("room");
    assert_eq!(p.at, 0);
}

#[test]
fn a_full_ring_places_nothing() {
    assert_eq!(place(0, 8, 0, 8, false), None);
    assert_eq!(place(MIXED, 8, 0, 8, true), None);
}

/// A mixed ring's wide completion takes two adjacent slots and moves the tail
/// by two, so the reader's own head arithmetic stays a plain slot count.
#[test]
fn a_wide_completion_on_a_mixed_ring_takes_two_adjacent_slots() {
    let p = place(MIXED, 2, 0, 8, true).expect("room");
    assert_eq!(p, Placement { filler_at: None, at: 2, advance: 2 });
}

/// The wrap rule: a wide completion whose two halves would land at opposite
/// ends of the array is preceded by a filler in the last slot, and starts
/// again at zero. Without the filler the skipped slot would never be consumed
/// and the head could never catch the tail.
#[test]
fn a_wide_completion_at_the_wrap_is_preceded_by_a_filler() {
    // Tail at the array's last slot, with room for the filler and both halves.
    let p = place(MIXED, 7, 4, 8, true).expect("room");
    assert_eq!(p, Placement { filler_at: Some(7), at: 0, advance: 3 });
}

/// The filler needs a slot of its own: a ring with no room at all cannot post
/// one, so the completion goes to the backlog rather than half-landing.
#[test]
fn the_filler_is_refused_when_the_ring_is_full() {
    // head=0 tail=8 on an 8-entry ring: full, and the tail is at the wrap.
    assert_eq!(place(MIXED, 8 + 7, 8, 8, true), None);
}

/// One free slot at the wrap is enough for the filler and nothing else: the
/// wide completion still has nowhere to go.
#[test]
fn one_free_slot_at_the_wrap_is_not_enough_for_a_wide_completion() {
    // tail=7, head=1 → 6 queued, 2 free. The filler takes one, leaving one,
    // and a wide completion needs two.
    assert_eq!(place(MIXED, 7, 1, 8, true), None);
    // tail=7, head=0 → 7 queued, 1 free: the filler alone exhausts the ring.
    assert_eq!(place(MIXED, 7, 0, 8, true), None);
}

/// A narrow completion is never refused for a wrap it cannot straddle.
#[test]
fn a_narrow_completion_never_needs_a_filler() {
    for tail in 0u32..16 {
        // Head trails by one so the ring is never full, whatever the tail is.
        let p = place(MIXED, tail, tail.wrapping_sub(1), 8, false);
        assert_eq!(p.unwrap().filler_at, None, "tail {tail}");
    }
}

/// A 32-byte ring never charges two slots and never fills: its array already
/// strides at 32, so the wrap is a slot boundary like any other.
#[test]
fn a_32_byte_ring_places_a_wide_completion_in_one_slot_anywhere() {
    for tail in 0u32..8 {
        let p = place(WIDE, tail, 0, 8, true).expect("room");
        assert_eq!(p, Placement { filler_at: None, at: tail, advance: 1 }, "tail {tail}");
    }
}

/// Every placement stays inside the array and never overlaps what the reader
/// has not consumed: walked over a full lap of a mixed ring with alternating
/// widths.
#[test]
fn a_lap_of_alternating_widths_never_overlaps_or_leaves_a_hole() {
    let entries = 8u32;
    let mut tail = 0u32;
    let mut wide = true;
    for _ in 0..40 {
        // Reap everything before each post so the ring is never the limit.
        let head = tail;
        let p = place(MIXED, tail, head, entries, wide).expect("empty ring has room");
        if let Some(f) = p.filler_at {
            assert_eq!(f, tail & (entries - 1), "the filler goes at the tail itself");
            assert_eq!(p.at, 0, "and the completion restarts at slot zero");
        } else {
            assert_eq!(p.at, tail & (entries - 1));
        }
        let need = if wide { 2 } else { 1 };
        assert!(p.at + need <= entries, "a completion must not straddle the wrap");
        tail = tail.wrapping_add(p.advance);
        wide = !wide;
    }
}
