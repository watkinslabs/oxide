use alloc::vec::Vec;

use super::*;
use crate::record::Record;

fn rec(n: u8) -> Record { Record { ty: 1305, text: Vec::from([n]) } }

#[test]
fn a_zero_limit_is_unlimited() {
    assert!(backlog_admits(0, 0));
    assert!(backlog_admits(1 << 20, 0));
}

/// The limit is a high-water mark the queue may sit exactly on; admission
/// stops once it is exceeded.
#[test]
fn the_limit_is_inclusive() {
    assert!(backlog_admits(63, 64));
    assert!(backlog_admits(64, 64));
    assert!(!backlog_admits(65, 64));
}

#[test]
fn a_full_queue_refuses_and_the_caller_learns_it() {
    let mut b = Backlog::new();
    for i in 0..3 { assert!(b.push(rec(i), 2)); }
    assert_eq!(b.len(), 3);
    assert!(!b.push(rec(9), 2), "the queue is past its limit");
    assert_eq!(b.len(), 3, "a refused record is not queued");
}

#[test]
fn records_come_back_oldest_first() {
    let mut b = Backlog::new();
    for i in 0..3 { b.push(rec(i), 0); }
    assert_eq!(b.pop().map(|r| r.text[0]), Some(0));
    assert_eq!(b.pop().map(|r| r.text[0]), Some(1));
    assert_eq!(b.pop().map(|r| r.text[0]), Some(2));
    assert_eq!(b.pop(), None);
    assert!(b.is_empty());
}

/// A consumer that registers late gets the history in the order it happened,
/// behind nothing: the hold queue drains onto the back of an empty queue.
#[test]
fn released_holds_arrive_in_order_behind_what_was_already_queued() {
    let mut b = Backlog::new();
    b.push(rec(10), 0);
    for i in 0..3 { assert!(b.hold(rec(i), 0)); }
    assert_eq!(b.hold_len(), 3);
    assert_eq!(b.len(), 1);
    b.release_hold();
    assert_eq!(b.hold_len(), 0);
    let order: Vec<u8> = core::iter::from_fn(|| b.pop()).map(|r| r.text[0]).collect();
    assert_eq!(order, Vec::from([10u8, 0, 1, 2]));
}

/// The hold queue is bounded by the same limit: a system with no consumer
/// cannot be made to accumulate records without bound.
#[test]
fn the_hold_queue_is_bounded_too() {
    let mut b = Backlog::new();
    for i in 0..3 { assert!(b.hold(rec(i), 2)); }
    assert!(!b.hold(rec(9), 2));
    assert_eq!(b.hold_len(), 3);
}
