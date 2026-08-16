// Reassembly.
//
// The interesting cases are the ones where a fragment does NOT belong: a
// sender that is not the one that started the frame, a fragment out of order,
// and a mix of protected and unprotected pieces. Accepting any of them is how
// a reassembly cache becomes a way to splice bytes into somebody else's frame.

use crate::limits;
use crate::rx::defrag::{Defrag, DefragCache};
use crate::tests_fixture as f;

#[test]
fn an_unfragmented_frame_passes_straight_through() {
    let mut c = DefragCache::default();
    let out = c.accept(f::PEER, 1, 0, false, false, 0, b"whole", 0);
    assert_eq!(out, Defrag::Complete(b"whole".to_vec()));
    assert!(c.is_empty());
}

#[test]
fn fragments_in_order_are_joined() {
    let mut c = DefragCache::default();
    assert_eq!(c.accept(f::PEER, 7, 0, true, false, 0, b"one", 0), Defrag::Held);
    assert_eq!(c.accept(f::PEER, 7, 1, true, false, 0, b"two", 0), Defrag::Held);
    assert_eq!(c.accept(f::PEER, 7, 2, false, false, 0, b"three", 0),
               Defrag::Complete(b"onetwothree".to_vec()));
    assert!(c.is_empty());
}

#[test]
fn a_fragment_out_of_order_is_dropped() {
    let mut c = DefragCache::default();
    c.accept(f::PEER, 7, 0, true, false, 0, b"one", 0);
    // Fragment 2 arrives while 1 is expected.
    assert_eq!(c.accept(f::PEER, 7, 2, false, false, 0, b"three", 0), Defrag::Dropped);
    // The entry is still waiting for 1, which is the fragment it expects.
    assert_eq!(c.accept(f::PEER, 7, 1, false, false, 0, b"two", 0),
               Defrag::Complete(b"onetwo".to_vec()));
}

#[test]
fn a_fragment_from_another_sender_does_not_join_this_frame() {
    let mut c = DefragCache::default();
    c.accept(f::PEER, 7, 0, true, false, 0, b"mine", 0);
    assert_eq!(c.accept(f::OTHER, 7, 1, false, false, 0, b"theirs", 0), Defrag::Dropped);
    assert_eq!(c.accept(f::PEER, 7, 1, false, false, 0, b"ok", 0),
               Defrag::Complete(b"mineok".to_vec()));
}

#[test]
fn a_fragment_with_another_sequence_number_does_not_join_this_frame() {
    let mut c = DefragCache::default();
    c.accept(f::PEER, 7, 0, true, false, 0, b"mine", 0);
    assert_eq!(c.accept(f::PEER, 8, 1, false, false, 0, b"other", 0), Defrag::Dropped);
}

#[test]
fn a_mix_of_protected_and_unprotected_fragments_is_refused() {
    // Splicing an unprotected fragment into a protected frame is the whole
    // point of the check.
    let mut c = DefragCache::default();
    c.accept(f::PEER, 7, 0, true, true, 0, b"protected", 0);
    assert_eq!(c.accept(f::PEER, 7, 1, false, false, 0, b"plain", 0), Defrag::Dropped);
    assert!(c.is_empty(), "the whole frame is abandoned, not just the bad fragment");
}

#[test]
fn fragments_protected_under_different_keys_are_refused() {
    let mut c = DefragCache::default();
    c.accept(f::PEER, 7, 0, true, true, 0, b"first", 0);
    assert_eq!(c.accept(f::PEER, 7, 1, false, true, 1, b"second", 0), Defrag::Dropped);
    assert!(c.is_empty());
}

#[test]
fn a_restarted_frame_replaces_the_half_finished_one() {
    let mut c = DefragCache::default();
    c.accept(f::PEER, 7, 0, true, false, 0, b"abandoned", 0);
    c.accept(f::PEER, 7, 0, true, false, 0, b"restart", 0);
    assert_eq!(c.len(), 1);
    assert_eq!(c.accept(f::PEER, 7, 1, false, false, 0, b"ed", 0),
               Defrag::Complete(b"restarted".to_vec()));
}

#[test]
fn a_fragment_with_no_entry_is_dropped() {
    let mut c = DefragCache::default();
    assert_eq!(c.accept(f::PEER, 7, 3, true, false, 0, b"orphan", 0), Defrag::Dropped);
}

#[test]
fn an_entry_whose_remaining_fragments_never_arrive_is_expired() {
    let mut c = DefragCache::default();
    c.accept(f::PEER, 7, 0, true, false, 0, b"lonely", 0);
    c.expire(limits::DEFRAG_TIMEOUT_NS - 1);
    assert_eq!(c.len(), 1);
    c.expire(limits::DEFRAG_TIMEOUT_NS);
    assert!(c.is_empty());
}

#[test]
fn several_senders_are_reassembled_at_once() {
    let mut c = DefragCache::default();
    c.accept(f::PEER, 1, 0, true, false, 0, b"a", 0);
    c.accept(f::OTHER, 1, 0, true, false, 0, b"b", 0);
    c.accept(f::AP, 1, 0, true, false, 0, b"c", 0);
    assert_eq!(c.len(), 3);
    assert_eq!(c.accept(f::OTHER, 1, 1, false, false, 0, b"B", 0),
               Defrag::Complete(b"bB".to_vec()));
    assert_eq!(c.accept(f::PEER, 1, 1, false, false, 0, b"A", 0),
               Defrag::Complete(b"aA".to_vec()));
}

#[test]
fn the_cache_holds_only_so_many_entries() {
    let mut c = DefragCache::default();
    for i in 0..(limits::NUM_DEFRAG_ENTRIES as u16 + 3) {
        let mut addr = f::PEER;
        addr.0[5] = i as u8;
        c.accept(addr, 1, 0, true, false, 0, b"x", 0);
    }
    assert_eq!(c.len(), limits::NUM_DEFRAG_ENTRIES);
}

#[test]
fn a_fragment_number_past_the_field_width_aborts_the_frame() {
    let mut c = DefragCache::default();
    c.accept(f::PEER, 1, 0, true, false, 0, b"x", 0);
    let mut n = 1u16;
    while (n as usize) < limits::MAX_FRAGMENTS {
        assert_eq!(c.accept(f::PEER, 1, n, true, false, 0, b"x", 0), Defrag::Held);
        n += 1;
    }
    assert_eq!(c.accept(f::PEER, 1, n, false, false, 0, b"x", 0), Defrag::Dropped);
}

#[test]
fn clearing_drops_everything() {
    let mut c = DefragCache::default();
    c.accept(f::PEER, 1, 0, true, false, 0, b"x", 0);
    c.clear();
    assert!(c.is_empty());
}
