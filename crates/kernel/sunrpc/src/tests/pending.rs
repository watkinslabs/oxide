// The outstanding-call table: xid occupancy and the reply-matching contract.

extern crate alloc;

use crate::err::RpcError;
use crate::xprt::{PendingTable, XidGen};

#[test]
fn an_inserted_xid_is_live_until_it_is_removed() {
    let t = PendingTable::new();
    assert!(!t.is_live(5));
    let c = t.insert(5).unwrap();
    assert!(t.is_live(5));
    assert_eq!(t.len(), 1);
    c.fail();
    t.remove(5);
    assert!(!t.is_live(5));
    assert!(t.is_empty());
}

#[test]
fn a_duplicate_xid_is_refused_rather_than_displacing_the_incumbent() {
    // Displacing it would leave the first caller waiting on a call nothing can
    // complete, while the second takes whichever reply arrives — and neither
    // caller could tell which answer it got.
    let t = PendingTable::new();
    let first = t.insert(5).unwrap();
    assert_eq!(t.insert(5).err(), Some(RpcError::XidMismatch));
    assert!(core::ptr::eq(alloc::sync::Arc::as_ptr(&first),
                          alloc::sync::Arc::as_ptr(&t.lookup(5).unwrap())));
}

#[test]
fn a_reply_for_an_unknown_xid_finds_nothing() {
    let t = PendingTable::new();
    t.insert(1).unwrap();
    assert!(t.lookup(2).is_none());
}

#[test]
fn the_first_reply_wins_and_a_duplicate_is_dropped() {
    // A duplicate is the normal case on a retransmitting transport. A second
    // DIFFERENT answer under the same xid is a server fault, and there is no
    // reason to prefer it over the first.
    let t = PendingTable::new();
    let c = t.insert(1).unwrap();
    assert!(c.complete(b"first"));
    assert!(!c.complete(b"second"));
    assert_eq!(c.take_reply().unwrap(), b"first".to_vec());
}

#[test]
fn a_failed_call_cannot_be_completed_afterwards() {
    let t = PendingTable::new();
    let c = t.insert(1).unwrap();
    c.fail();
    assert!(c.is_done());
    assert!(!c.complete(b"late"));
    assert!(c.take_reply().is_none());
}

#[test]
fn a_completed_call_is_not_downgraded_by_a_later_failure() {
    let t = PendingTable::new();
    let c = t.insert(1).unwrap();
    c.complete(b"answer");
    c.fail();
    assert_eq!(c.take_reply().unwrap(), b"answer".to_vec());
}

#[test]
fn draining_empties_the_table_and_hands_back_every_call() {
    let t = PendingTable::new();
    for x in 1..=4 { t.insert(x).unwrap(); }
    let drained = t.drain();
    assert_eq!(drained.len(), 4);
    assert!(t.is_empty());
    for c in &drained { c.fail(); assert!(c.is_done()); }
}

#[test]
fn xids_increment_monotonically_from_their_seed() {
    let g = XidGen::new(0x1000);
    assert_eq!((g.alloc(), g.alloc(), g.alloc()), (0x1000, 0x1001, 0x1002));
    assert_eq!(g.peek(), 0x1003);
}

#[test]
fn the_xid_counter_wraps_without_panicking() {
    let g = XidGen::new(u32::MAX);
    assert_eq!(g.alloc(), u32::MAX);
    assert_eq!(g.alloc(), 0);
}

#[test]
fn a_wrapped_xid_still_colliding_with_a_live_call_is_refused() {
    // The counter is not the authority on occupancy; the table is.
    let t = PendingTable::new();
    t.insert(0).unwrap();
    assert_eq!(t.insert(0).err(), Some(RpcError::XidMismatch));
}
