use super::*;

fn fixture(n: usize) -> (NetIovArea, UserRefs) {
    (NetIovArea::new(n), UserRefs::new(n).unwrap())
}

/// The whole life of one buffer: handed out once, in flight once, returned
/// once, free.
#[test]
fn a_buffer_handed_out_once_is_freed_by_one_refill() {
    let (nia, urefs) = fixture(4);
    nia.niovs[2].fragment(1);
    urefs.take(2);
    assert_eq!(refill(&nia, &urefs, 2), Refill::Freed);
    assert_eq!(urefs.get(2), 0);
    assert_eq!(nia.niovs[2].refs(), 0);
}

/// The defect this module exists to prevent: a caller that returns the same
/// buffer twice must not drive the pool count to zero a second time. If it
/// could, the buffer would be handed to a new owner while the stack still had
/// it.
#[test]
fn a_buffer_returned_twice_is_freed_once() {
    let (nia, urefs) = fixture(4);
    nia.niovs[0].fragment(1);
    urefs.take(0);
    assert_eq!(refill(&nia, &urefs, 0), Refill::Freed);
    assert_eq!(refill(&nia, &urefs, 0), Refill::NotHeld);
    assert_eq!(refill(&nia, &urefs, 0), Refill::NotHeld);
    assert_eq!(nia.niovs[0].refs(), 0);
}

/// A buffer the caller never held is not a buffer it can return.
#[test]
fn a_buffer_the_caller_never_held_is_not_touched() {
    let (nia, urefs) = fixture(4);
    nia.niovs[1].fragment(1);
    assert_eq!(refill(&nia, &urefs, 1), Refill::NotHeld);
    // The pool reference survived, which is the point: the stack still owns it.
    assert_eq!(nia.niovs[1].refs(), 1);
}

/// The user reference goes first and the pool reference is only touched if one
/// was really spent. A buffer the stack still holds a second reference to
/// stays in flight even though the caller returned its own.
#[test]
fn a_buffer_the_stack_still_holds_stays_in_flight() {
    let (nia, urefs) = fixture(4);
    nia.niovs[3].fragment(2);
    urefs.take(3);
    assert_eq!(refill(&nia, &urefs, 3), Refill::StillInFlight);
    assert_eq!(nia.niovs[3].refs(), 1);
    assert_eq!(urefs.get(3), 0);
}

/// A buffer handed out twice needs both returns before it is free.
#[test]
fn a_buffer_handed_out_twice_needs_both_returns() {
    let (nia, urefs) = fixture(2);
    nia.niovs[0].fragment(2);
    urefs.take(0);
    urefs.take(0);
    assert_eq!(refill(&nia, &urefs, 0), Refill::StillInFlight);
    assert_eq!(refill(&nia, &urefs, 0), Refill::Freed);
    assert_eq!(refill(&nia, &urefs, 0), Refill::NotHeld);
}

/// An index past the area is a malformed entry, not a panic: the entry came
/// out of a ring userspace writes without the kernel watching.
#[test]
fn an_index_past_the_area_is_refused() {
    let (nia, urefs) = fixture(2);
    assert_eq!(refill(&nia, &urefs, 2), Refill::NotHeld);
    assert_eq!(refill(&nia, &urefs, u32::MAX), Refill::NotHeld);
}
