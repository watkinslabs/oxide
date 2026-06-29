//! EPOLLEXCLUSIVE wake-one semantics (Linux fs/eventpoll.c
//! `add_wait_queue_exclusive` + `__wake_up_common` nr_exclusive==1).
//!
//! When N epoll instances each add the SAME listening socket with
//! `EPOLLEXCLUSIVE`, a single incoming-connection readiness event must wake
//! exactly ONE of them (thundering-herd avoidance for `accept(2)` load
//! balancing) — not all N. Non-exclusive subscribers are unaffected: they all
//! still wake. An exclusive subscriber whose interest mask does NOT match is
//! skipped without consuming the single exclusive wake, so a later interested
//! exclusive subscriber still gets it.
//!
//! Own test binary; `EpollNotify` impl counts wakes via an atomic, no global
//! vfs state mutated → no serial guard needed.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use vfs::{EpollNotify, PollSubscribers, POLL_IN, POLL_OUT, POLL_ERR};

struct Counter { hits: AtomicU32 }
impl Counter { fn new() -> Arc<Self> { Arc::new(Self { hits: AtomicU32::new(0) }) } }
impl EpollNotify for Counter {
    fn notify(&self) { self.hits.fetch_add(1, Ordering::Relaxed); }
}
fn hits(c: &Arc<Counter>) -> u32 { c.hits.load(Ordering::Relaxed) }
fn weak(c: &Arc<Counter>) -> Weak<dyn EpollNotify> {
    Arc::downgrade(&(c.clone() as Arc<dyn EpollNotify>))
}

// Two EPOLLEXCLUSIVE subscribers, both interested: one readiness event wakes
// exactly ONE of them, never both.
#[test]
fn exclusive_event_wakes_exactly_one() {
    let subs = PollSubscribers::new();
    let a = Counter::new();
    let b = Counter::new();
    subs.subscribe_exclusive(1, weak(&a), POLL_IN);
    subs.subscribe_exclusive(2, weak(&b), POLL_IN);

    subs.notify_mask(POLL_IN);
    assert_eq!(hits(&a) + hits(&b), 1, "EPOLLEXCLUSIVE: exactly one exclusive waiter woken");
}

// Non-exclusive subscribers are NOT rate-limited by the exclusive wake budget:
// every interested non-exclusive one wakes, plus exactly one exclusive one.
#[test]
fn nonexclusive_all_wake_plus_one_exclusive() {
    let subs = PollSubscribers::new();
    let shared = Counter::new();      // plain subscriber, always woken
    let ex1 = Counter::new();
    let ex2 = Counter::new();
    subs.subscribe_mask(1, weak(&shared), POLL_IN);
    subs.subscribe_exclusive(2, weak(&ex1), POLL_IN);
    subs.subscribe_exclusive(3, weak(&ex2), POLL_IN);

    subs.notify_mask(POLL_IN);
    assert_eq!(hits(&shared), 1, "non-exclusive subscriber always woken");
    assert_eq!(hits(&ex1) + hits(&ex2), 1, "exactly one of the two exclusive waiters woken");
}

// An exclusive subscriber whose mask does NOT match the event is skipped and
// does NOT consume the single exclusive wake — the interested exclusive one
// still gets woken (Linux: a key-check miss is not counted in nr_exclusive).
#[test]
fn uninterested_exclusive_does_not_consume_the_wake() {
    let subs = PollSubscribers::new();
    let writer_ex = Counter::new();   // exclusive, wants POLLOUT (won't match POLLIN)
    let reader_ex = Counter::new();   // exclusive, wants POLLIN  (will match)
    subs.subscribe_exclusive(1, weak(&writer_ex), POLL_OUT);
    subs.subscribe_exclusive(2, weak(&reader_ex), POLL_IN);

    subs.notify_mask(POLL_IN);
    assert_eq!(hits(&writer_ex), 0, "POLLOUT-only exclusive waiter not woken by POLLIN");
    assert_eq!(hits(&reader_ex), 1, "interested exclusive waiter still woken despite earlier miss");
}

// The unconditional broadcast `notify()` (teardown / POLLFREE path) ignores the
// exclusive budget and wakes EVERY live subscriber, exclusive or not.
#[test]
fn broadcast_notify_wakes_all_exclusive() {
    let subs = PollSubscribers::new();
    let a = Counter::new();
    let b = Counter::new();
    subs.subscribe_exclusive(1, weak(&a), POLL_IN);
    subs.subscribe_exclusive(2, weak(&b), POLL_IN);

    subs.notify();
    assert_eq!(hits(&a), 1, "broadcast wakes first exclusive waiter");
    assert_eq!(hits(&b), 1, "broadcast wakes second exclusive waiter too");
}

// ERR/HUP (always-reported) under exclusive still respects the one-wake budget
// for exclusive waiters: exactly one exclusive woken even though both "match".
#[test]
fn always_wake_err_still_limits_exclusive_to_one() {
    let subs = PollSubscribers::new();
    let a = Counter::new();
    let b = Counter::new();
    // neither asked for POLLERR, but it is always-reported.
    subs.subscribe_exclusive(1, weak(&a), POLL_IN);
    subs.subscribe_exclusive(2, weak(&b), POLL_IN);

    subs.notify_mask(POLL_ERR);
    assert_eq!(hits(&a) + hits(&b), 1, "always-wake event still limits exclusive waiters to one");
}

// EPOLL_CTL_MOD re-add can flip an exclusive subscriber back to non-exclusive
// (and vice-versa); the latest registration's flag wins.
#[test]
fn re_add_replaces_exclusive_flag() {
    let subs = PollSubscribers::new();
    let a = Counter::new();
    let b = Counter::new();
    subs.subscribe_exclusive(1, weak(&a), POLL_IN);
    subs.subscribe_exclusive(2, weak(&b), POLL_IN);
    // promote `a` to a plain (non-exclusive) subscriber via MOD.
    subs.subscribe_mask(1, weak(&a), POLL_IN);

    subs.notify_mask(POLL_IN);
    assert_eq!(hits(&a), 1, "re-added non-exclusive subscriber always woken");
    assert_eq!(hits(&b), 1, "the sole remaining exclusive subscriber woken");
}
