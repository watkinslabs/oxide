// Servicing-context growth. The contract these encode is the reason the pool
// exists at all: a request that blocks for the lifetime of its helper program
// must never be the reason a DIFFERENT request goes unserved.

use crate::pool::{Grow, Pool};

/// Boot's first context: reserve a slot, then report it reached its loop.
fn boot(pool: &Pool) {
    assert!(pool.reserve(), "the first slot is always available");
    pool.ready();
}

#[test]
fn a_context_that_takes_a_request_leaves_a_successor_behind() {
    let pool = Pool::new(4);
    boot(&pool);
    // The one idle context takes a request. It is about to block for as long as
    // the helper program runs, so a successor must be started.
    assert_eq!(pool.claim(), Grow::Spawn);
    assert_eq!(pool.counts(), (2, 0));
    pool.ready(); // the successor reaches its loop
    assert_eq!(pool.counts(), (2, 1));
}

#[test]
fn a_second_request_is_served_while_the_first_still_blocks() {
    // The deadlock this pool exists to prevent: a helper that asks the kernel
    // for another helper. The nested request must be claimable by a context
    // that is NOT the one waiting for the program that issued it.
    let pool = Pool::new(4);
    boot(&pool);
    pool.claim();       // outer request; its context now blocks
    pool.ready();       // successor available
    let (_, idle) = pool.counts();
    assert_eq!(idle, 1, "a context is free while the outer request blocks");
    assert_eq!(pool.claim(), Grow::Spawn, "the nested request is taken by the free context");
    assert_eq!(pool.counts(), (3, 0));
}

#[test]
fn an_idle_peer_is_enough_and_the_pool_does_not_grow() {
    let pool = Pool::new(4);
    boot(&pool);
    pool.claim();
    pool.ready();
    pool.ready();       // two idle contexts (one blocked context, two waiting)
    assert_eq!(pool.claim(), Grow::Enough, "an idle peer already covers the queue");
    assert_eq!(pool.counts().0, 2, "no slot reserved when a peer is idle");
}

#[test]
fn the_pool_stops_growing_at_its_cap() {
    let pool = Pool::new(2);
    boot(&pool);
    assert_eq!(pool.claim(), Grow::Spawn);
    pool.ready();
    assert_eq!(pool.claim(), Grow::Enough, "at the cap there is nothing left to start");
    assert_eq!(pool.counts(), (2, 0));
    assert_eq!(pool.cap(), 2);
}

#[test]
fn a_failed_start_gives_its_reservation_back() {
    let pool = Pool::new(2);
    boot(&pool);
    assert_eq!(pool.claim(), Grow::Spawn);
    pool.spawn_failed();
    assert_eq!(pool.counts(), (1, 0), "the slot is free for a later claim to retry");
    // The context that failed to gain a successor finishes its request and is
    // idle again; the next claim may try to grow once more.
    pool.released();
    assert_eq!(pool.claim(), Grow::Spawn);
}

#[test]
fn a_finished_request_returns_its_context_to_the_idle_set() {
    let pool = Pool::new(4);
    boot(&pool);
    pool.claim();
    pool.ready();
    pool.released();    // the first context's request completed
    assert_eq!(pool.counts(), (2, 2));
}

#[test]
fn every_queued_request_can_block_at_once_up_to_the_cap() {
    // With N contexts started on demand, N simultaneously blocking requests
    // leave the pool full but never leave a claimable request unclaimed while
    // the cap allows another context.
    const CAP: u32 = 8;
    let pool = Pool::new(CAP);
    boot(&pool);
    for _ in 0..CAP - 1 {
        assert_eq!(pool.claim(), Grow::Spawn, "each blocking request gains a successor");
        pool.ready();
    }
    assert_eq!(pool.counts(), (CAP, 1));
    assert_eq!(pool.claim(), Grow::Enough, "the cap is reached");
    assert_eq!(pool.counts(), (CAP, 0));
}

#[test]
fn a_miscounted_release_cannot_wrap_the_idle_count() {
    let pool = Pool::new(2);
    pool.claim(); // no context was ever idle
    assert_eq!(pool.counts().1, 0, "idle saturates at zero rather than wrapping");
    pool.spawn_failed();
    pool.spawn_failed();
    assert_eq!(pool.counts().0, 0, "total saturates at zero rather than wrapping");
}
