//! Per-inode poll-subscriber mask filtering (Linux fs/eventpoll.c
//! `ep_poll_callback` key check + always-reported `EPOLLERR|EPOLLHUP`).
//!
//! `PollSubscribers::notify_mask(events)` must wake ONLY subscribers
//! whose interest intersects `events`, EXCEPT that `POLL_ERR|POLL_HUP`
//! wake every subscriber regardless of interest. The legacy `notify()`
//! wakes everyone unconditionally. Without mask filtering an
//! `EPOLLIN`-only epoll waiter is spuriously woken by a pure
//! `EPOLLOUT` writability transition on the inode (and vice-versa) —
//! the cross-interest spurious-wakeup this regression test pins.
//!
//! Own test binary; `EpollNotify` impl counts wakes via an atomic, no
//! global vfs state mutated → no serial guard needed.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use vfs::{EpollNotify, PollSubscribers, POLL_IN, POLL_OUT, POLL_ERR, POLL_HUP};

/// Test subscriber: bumps its counter every time the inode wakes it.
struct Counter { hits: AtomicU32 }
impl Counter { fn new() -> Arc<Self> { Arc::new(Self { hits: AtomicU32::new(0) }) } }
impl EpollNotify for Counter {
    fn notify(&self) { self.hits.fetch_add(1, Ordering::Relaxed); }
}
fn hits(c: &Arc<Counter>) -> u32 { c.hits.load(Ordering::Relaxed) }
fn weak(c: &Arc<Counter>) -> Weak<dyn EpollNotify> {
    Arc::downgrade(&(c.clone() as Arc<dyn EpollNotify>))
}

#[test]
fn notify_mask_skips_uninterested_subscriber() {
    let subs = PollSubscribers::new();
    let reader = Counter::new();   // wants POLLIN only
    let writer = Counter::new();   // wants POLLOUT only
    subs.subscribe_mask(1, weak(&reader), POLL_IN);
    subs.subscribe_mask(2, weak(&writer), POLL_OUT);

    // A pure readability transition must wake the reader, NOT the writer.
    subs.notify_mask(POLL_IN);
    assert_eq!(hits(&reader), 1, "POLLIN waiter woken by POLLIN event");
    assert_eq!(hits(&writer), 0, "POLLOUT-only waiter must NOT wake on POLLIN");

    // A pure writability transition wakes the writer, NOT the reader.
    subs.notify_mask(POLL_OUT);
    assert_eq!(hits(&reader), 1, "POLLIN-only waiter must NOT wake on POLLOUT");
    assert_eq!(hits(&writer), 1, "POLLOUT waiter woken by POLLOUT event");
}

#[test]
fn err_and_hup_always_wake_regardless_of_interest() {
    let subs = PollSubscribers::new();
    let reader = Counter::new();
    let writer = Counter::new();
    subs.subscribe_mask(1, weak(&reader), POLL_IN);
    subs.subscribe_mask(2, weak(&writer), POLL_OUT);

    // POLLERR is delivered to every subscriber even though neither asked.
    subs.notify_mask(POLL_ERR);
    assert_eq!(hits(&reader), 1, "POLLERR always reported");
    assert_eq!(hits(&writer), 1, "POLLERR always reported");

    // Same for POLLHUP (peer hangup).
    subs.notify_mask(POLL_HUP);
    assert_eq!(hits(&reader), 2, "POLLHUP always reported");
    assert_eq!(hits(&writer), 2, "POLLHUP always reported");
}

#[test]
fn notify_mask_zero_wakes_nobody() {
    let subs = PollSubscribers::new();
    let c = Counter::new();
    subs.subscribe_mask(1, weak(&c), POLL_IN);
    subs.notify_mask(0);
    assert_eq!(hits(&c), 0, "keyless (events==0) wake fires nobody");
}

#[test]
fn plain_subscribe_is_interested_in_everything() {
    // subscribe() defaults mask=!0 → woken by any masked event, preserving
    // the pre-mask wake-all behavior every existing net/fs/tty caller relies on.
    let subs = PollSubscribers::new();
    let c = Counter::new();
    subs.subscribe(7, weak(&c));
    subs.notify_mask(POLL_OUT);
    assert_eq!(hits(&c), 1, "all-interest subscriber woken by POLLOUT");
    subs.notify_mask(POLL_IN);
    assert_eq!(hits(&c), 2, "all-interest subscriber woken by POLLIN");
}

#[test]
fn legacy_notify_still_wakes_all_unconditionally() {
    let subs = PollSubscribers::new();
    let reader = Counter::new();
    let writer = Counter::new();
    subs.subscribe_mask(1, weak(&reader), POLL_IN);
    subs.subscribe_mask(2, weak(&writer), POLL_OUT);
    subs.notify();
    assert_eq!(hits(&reader), 1, "notify() wakes all regardless of interest");
    assert_eq!(hits(&writer), 1, "notify() wakes all regardless of interest");
}

#[test]
fn subscribe_mask_mod_replaces_interest() {
    // Re-subscribing the same id mirrors epoll_ctl(EPOLL_CTL_MOD): the
    // interest mask is replaced, not merged.
    let subs = PollSubscribers::new();
    let c = Counter::new();
    subs.subscribe_mask(3, weak(&c), POLL_IN);
    subs.subscribe_mask(3, weak(&c), POLL_OUT); // MOD: now POLLOUT only
    subs.notify_mask(POLL_IN);
    assert_eq!(hits(&c), 0, "old POLLIN interest dropped by MOD");
    subs.notify_mask(POLL_OUT);
    assert_eq!(hits(&c), 1, "new POLLOUT interest honored after MOD");
}

#[test]
fn dead_subscriber_is_pruned_not_woken() {
    let subs = PollSubscribers::new();
    let live = Counter::new();
    subs.subscribe_mask(1, weak(&live), POLL_IN);
    {
        let dead = Counter::new();
        subs.subscribe_mask(2, weak(&dead), POLL_IN);
        // dead drops here; its Weak no longer upgrades.
    }
    subs.notify_mask(POLL_IN);
    assert_eq!(hits(&live), 1, "live subscriber woken");
    assert!(subs.has_subscribers(), "live subscriber still registered after prune");
}
