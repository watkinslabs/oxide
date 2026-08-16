// Provenance: ALSA's control-event contract — a subscriber sees only events
// queued after it subscribed, the per-card queue is bounded and drops the
// oldest, and the cursor is per open description.

use super::*;
use crate::uapi::CTL_EVENT_MASK_VALUE;

fn key(raw: u32) -> crate::SoundOwnerKey { crate::SoundOwnerKey::from_raw(raw).unwrap() }

#[test]
fn a_subscriber_sees_only_events_queued_after_it_subscribed() {
    let owner = key(0x7001);
    unregister_card(owner);
    push(owner, CTL_EVENT_MASK_VALUE, 1, &ElemId::mixer(b"Master Playback Volume", 0));
    let cursor = latest_seq(owner);
    assert!(next_after(owner, cursor).is_none());
    push(owner, CTL_EVENT_MASK_VALUE, 2, &ElemId::mixer(b"Headphone Jack", 0));
    let event = next_after(owner, cursor).unwrap();
    assert_eq!(event.numid, 2);
    assert_eq!(event.mask, CTL_EVENT_MASK_VALUE);
    // Advancing the cursor past it drains the queue for that reader.
    assert!(next_after(owner, event.seq).is_none());
    unregister_card(owner);
}

#[test]
fn the_queue_is_bounded_and_drops_the_oldest() {
    let owner = key(0x7002);
    unregister_card(owner);
    for numid in 0..(RING_DEPTH as u32 + 8) {
        push(owner, CTL_EVENT_MASK_VALUE, numid, &ElemId::mixer(b"Master Playback Volume", 0));
    }
    let oldest = next_after(owner, 0).unwrap();
    // Eight events were dropped, so the oldest retained one is the ninth.
    assert_eq!(oldest.numid, 8);
    assert_eq!(oldest.seq, 9);
    unregister_card(owner);
}

#[test]
fn cursors_are_owner_scoped_and_survive_unrelated_cards() {
    let (a, b) = (key(0x7003), key(0x7004));
    unregister_card(a);
    unregister_card(b);
    push(a, CTL_EVENT_MASK_VALUE, 1, &ElemId::mixer(b"A", 0));
    assert!(next_after(b, 0).is_none());
    push(b, CTL_EVENT_MASK_VALUE, 9, &ElemId::mixer(b"B", 0));
    assert_eq!(next_after(a, 0).unwrap().numid, 1);
    assert_eq!(next_after(b, 0).unwrap().numid, 9);
    unregister_card(a);
    unregister_card(b);
}

#[test]
fn private_data_packing_round_trips_subscription_and_cursor() {
    assert_eq!(unpack(pack(true, 0)), (true, 0));
    assert_eq!(unpack(pack(false, 0)), (false, 0));
    assert_eq!(unpack(pack(true, 12345)), (true, 12345));
    // An unsubscribed description is distinguishable from a subscribed one at
    // cursor zero — the bit, not the cursor, is the admission test.
    assert_ne!(pack(true, 0), pack(false, 0));
}
