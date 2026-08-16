// Replay detection.
//
// A replay check that accepts a packet number it has already seen delivers a
// captured frame a second time and nothing anywhere reports a problem: the
// frame decrypts, its integrity code is genuine, and the stack above sees a
// duplicate it cannot distinguish from a retransmission. These tests are the
// only place that failure becomes visible.

use crate::crypto::pn::{Pn, RxPn, TxPn, NON_QOS_SLOT, NUM_REPLAY_SLOTS, PN_MAX};

#[test]
fn a_number_equal_to_the_last_accepted_is_rejected() {
    let mut r = RxPn::default();
    assert!(r.accept(Some(0), Pn(5)));
    assert!(!r.accept(Some(0), Pn(5)), "the same number twice is a replay");
    assert_eq!(r.last(Some(0)), Some(Pn(5)));
}

#[test]
fn a_number_below_the_last_accepted_is_rejected() {
    let mut r = RxPn::default();
    assert!(r.accept(Some(0), Pn(100)));
    for lower in [99u64, 50, 1, 0] {
        assert!(!r.accept(Some(0), Pn(lower)), "pn={lower} is behind 100");
    }
    assert_eq!(r.last(Some(0)), Some(Pn(100)));
}

#[test]
fn a_number_above_the_last_accepted_is_accepted_and_advances() {
    let mut r = RxPn::default();
    assert!(r.accept(Some(0), Pn(1)));
    assert!(r.accept(Some(0), Pn(2)));
    // A gap is fine: frames are lost on the air all the time.
    assert!(r.accept(Some(0), Pn(1000)));
    assert_eq!(r.last(Some(0)), Some(Pn(1000)));
    assert!(!r.accept(Some(0), Pn(999)));
}

#[test]
fn a_rejected_number_does_not_advance_the_counter() {
    // If a rejected replay moved the counter, an attacker replaying a frame
    // with a high number would push it past every genuine frame still in
    // flight and silently drop all of them.
    let mut r = RxPn::default();
    r.accept(Some(0), Pn(10));
    r.accept(Some(0), Pn(3));
    assert_eq!(r.last(Some(0)), Some(Pn(10)));
}

#[test]
fn the_first_frame_on_a_slot_is_accepted_at_any_value() {
    let mut r = RxPn::default();
    assert!(r.accept(Some(4), Pn(0)));
    let mut r2 = RxPn::default();
    assert!(r2.accept(Some(4), Pn(PN_MAX)));
}

#[test]
fn counters_are_independent_per_traffic_identifier() {
    let mut r = RxPn::default();
    // Voice traffic runs ahead of background traffic; neither may reject the
    // other's frames.
    assert!(r.accept(Some(6), Pn(500)));
    assert!(r.accept(Some(1), Pn(2)), "a low number on a different identifier is new");
    assert!(r.accept(Some(1), Pn(3)));
    assert!(!r.accept(Some(1), Pn(3)));
    assert_eq!(r.last(Some(6)), Some(Pn(500)));
    assert_eq!(r.last(Some(1)), Some(Pn(3)));
    // And every identifier really does have its own slot.
    for tid in 0..16u8 {
        let mut fresh = RxPn::default();
        assert!(fresh.accept(Some(tid), Pn(7)));
        for other in 0..16u8 {
            if other == tid { continue; }
            assert!(fresh.accept(Some(other), Pn(1)),
                    "tid {other} must not be blocked by tid {tid}");
        }
    }
}

#[test]
fn a_frame_with_no_identifier_has_its_own_slot() {
    let mut r = RxPn::default();
    assert!(r.accept(None, Pn(9)));
    // Best-effort traffic is identifier zero and must not share the slot that
    // frames carrying no identifier use.
    assert!(r.accept(Some(0), Pn(1)));
    assert_eq!(r.last(None), Some(Pn(9)));
    assert_eq!(r.last(Some(0)), Some(Pn(1)));
    assert_eq!(NON_QOS_SLOT, NUM_REPLAY_SLOTS - 1);
}

#[test]
fn an_out_of_range_identifier_falls_into_the_no_identifier_slot() {
    let mut r = RxPn::default();
    assert!(r.accept(Some(200), Pn(4)));
    assert_eq!(r.last(None), Some(Pn(4)));
}

#[test]
fn would_accept_does_not_advance_anything() {
    let mut r = RxPn::default();
    assert!(r.would_accept(Some(0), Pn(5)));
    assert!(r.would_accept(Some(0), Pn(5)), "a peek must be repeatable");
    assert!(r.accept(Some(0), Pn(5)));
    assert!(!r.would_accept(Some(0), Pn(5)));
}

#[test]
fn a_seeded_counter_rejects_everything_up_to_its_seed() {
    // Installing a key with a starting counter must not leave the link
    // accepting the frames sent before the rekey.
    let mut r = RxPn::seeded(Pn(1000));
    assert!(!r.accept(Some(0), Pn(999)));
    assert!(!r.accept(Some(0), Pn(1000)));
    assert!(r.accept(Some(0), Pn(1001)));
    // Every identifier is seeded, not just the first.
    for tid in 0..16u8 {
        let mut fresh = RxPn::seeded(Pn(50));
        assert!(!fresh.accept(Some(tid), Pn(50)), "tid {tid} was not seeded");
    }
}

#[test]
fn a_reset_forgets_everything() {
    let mut r = RxPn::default();
    r.accept(Some(0), Pn(77));
    r.reset();
    assert_eq!(r.last(Some(0)), None);
    assert!(r.accept(Some(0), Pn(1)));
}

#[test]
fn the_transmit_counter_never_repeats_and_never_wraps() {
    let mut t = TxPn::new(0);
    let mut last = 0u64;
    for _ in 0..1000 {
        let pn = t.take().expect("counter has room");
        assert!(pn.0 > last, "the transmit counter must strictly increase");
        last = pn.0;
    }
    // At the top it refuses rather than wrapping: a wrapped counter repeats a
    // nonce, which is the one failure these ciphers cannot survive.
    let mut exhausted = TxPn::new(PN_MAX);
    assert_eq!(exhausted.take(), None);
}

#[test]
fn packet_numbers_round_trip_through_their_wire_bytes() {
    for v in [0u64, 1, 0xff, 0x0100, 0x123456789a, PN_MAX] {
        let pn = Pn(v);
        assert_eq!(Pn::from_bytes(&pn.to_bytes()), pn, "value {v:#x}");
    }
    // Most significant byte first.
    assert_eq!(Pn(0x0102_0304_0506).to_bytes(), [1, 2, 3, 4, 5, 6]);
}
