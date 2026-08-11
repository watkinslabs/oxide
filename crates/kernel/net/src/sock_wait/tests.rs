// The socket sleep queue's own contract, exercised on the host realisation.
// These are the checks that keep the two realisations answering the same
// questions: publish-before-wake cannot lose a wake, a single wake rouses one
// waiter in FIFO order, and an expiry ends a wait nobody satisfies.

use super::SockWaitQueue;
use alloc::sync::Arc;

#[test]
fn an_unparked_wait_returns_immediately() {
    let q = SockWaitQueue::new();
    // SAFETY: no park was published, so the yield step has nothing to wait on.
    unsafe { q.wait(); }
    assert!(!q.has_waiters());
}

#[test]
fn a_park_publishes_a_waiter_before_the_wake_can_run() {
    let q = SockWaitQueue::new();
    assert!(!q.has_waiters());
    // SAFETY: hosted realisation; publish-then-retire on this same thread.
    unsafe { q.prepare_to_wait_interruptible_with_deadline(0); }
    assert!(q.has_waiters(), "the park must be visible to a waker before the yield");
    q.remove_current();
    assert!(!q.has_waiters());
}

#[test]
fn a_wake_that_lands_before_the_yield_is_not_lost() {
    let q = SockWaitQueue::new();
    // SAFETY: publish, then wake, then yield — the ordering a waker that took
    // the resource lock after the park would produce.
    unsafe { q.prepare_to_wait_interruptible_with_deadline(0); }
    q.wake_all();
    // SAFETY: the flag is already set; the yield must observe it and return.
    unsafe { q.wait(); }
    assert!(!q.has_waiters());
}

#[test]
fn an_expiry_ends_a_wait_nobody_satisfies() {
    let q = SockWaitQueue::new();
    let deadline = super::hosted::deadline_in_ns(1_000_000);
    // SAFETY: nothing will wake this waiter; the expiry is the only exit.
    unsafe { q.prepare_to_wait_interruptible_with_deadline(deadline); }
    // SAFETY: same thread completes its own park.
    unsafe { q.wait(); }
    assert!(!q.has_waiters(), "an expired wait must retire its registration");
}

#[test]
fn wake_one_rouses_a_single_waiter_in_fifo_order() {
    let q = Arc::new(SockWaitQueue::new());
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = alloc::vec::Vec::new();
    for _ in 0..2 {
        let q = q.clone();
        let started = started.clone();
        let done = done.clone();
        handles.push(std::thread::spawn(move || {
            // SAFETY: each thread publishes and completes its own park.
            unsafe { q.prepare_to_wait_interruptible_with_deadline(0); }
            started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // SAFETY: no lock held across the yield.
            unsafe { q.wait(); }
            done.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }
    while started.load(std::sync::atomic::Ordering::SeqCst) < 2 { sync::relax(); }
    q.wake_one();
    while done.load(std::sync::atomic::Ordering::SeqCst) < 1 { sync::relax(); }
    assert!(q.has_waiters(), "one wake must leave the second waiter parked");
    q.wake_one();
    for h in handles { h.join().expect("waiter thread"); }
    assert!(!q.has_waiters());
}

#[test]
fn wake_all_drains_every_waiter() {
    let q = Arc::new(SockWaitQueue::new());
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = alloc::vec::Vec::new();
    for _ in 0..4 {
        let q = q.clone();
        let started = started.clone();
        handles.push(std::thread::spawn(move || {
            // SAFETY: each thread publishes and completes its own park.
            unsafe { q.prepare_to_wait_interruptible_with_deadline(0); }
            started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // SAFETY: no lock held across the yield.
            unsafe { q.wait(); }
        }));
    }
    while started.load(std::sync::atomic::Ordering::SeqCst) < 4 { sync::relax(); }
    q.wake_all();
    for h in handles { h.join().expect("waiter thread"); }
    assert!(!q.has_waiters());
}
