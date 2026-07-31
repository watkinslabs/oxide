// B1422 — lost-wakeup regression test for the counter read/write path. As in
// `pipe/ring.rs`'s equivalent test, `sched::live` has no runqueue under a
// hosted `cargo test` build, so `WaitList::park`/`schedule` are unreachable
// there; this drives real OS threads against the SAME `EventfdGate` lock
// production code uses, with a wait-list stand-in as lossy as the real one
// (a wake is dropped if nobody is registered yet — unlike
// `std::thread::park`/`unpark`, whose token persists regardless of call
// order and would validate nothing about the fix).
//
// The rest cover the observable eventfd(2) surface through the real inode:
// record sizes, the sentinel rejection, semaphore drain, EAGAIN on both
// directions and the fdinfo rendering.

use super::*;
use std::sync::{Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

fn data(count: u64, semaphore: bool) -> EventfdData {
    EventfdData {
        counter: Spinlock::new(count), semaphore, id: 0,
        read_waiters: WaitList::new(), write_waiters: WaitList::new(),
    }
}

#[derive(Default)]
struct LossyWaitList {
    slot: Mutex<Option<std::sync::Arc<(Mutex<bool>, Condvar)>>>,
}
impl LossyWaitList {
    fn register(&self) -> std::sync::Arc<(Mutex<bool>, Condvar)> {
        let slot = std::sync::Arc::new((Mutex::new(false), Condvar::new()));
        *self.slot.lock().unwrap() = Some(slot.clone());
        slot
    }
    fn wake(&self) {
        if let Some(slot) = self.slot.lock().unwrap().take() {
            *slot.0.lock().unwrap() = true;
            slot.1.notify_all();
        }
    }
}

/// Mirrors the FIXED `read`: one critical section over `d.counter` covers
/// "is it zero" and "register as parked", so `writer_bump`'s
/// mutate-then-wake can never land in the gap.
fn reader_once(d: &EventfdData, waiters: &LossyWaitList) -> u64 {
    loop {
        if let Some(v) = try_drain(d) { return v; }
        let g = d.counter.lock();
        if *g != 0 { drop(g); continue; }
        let slot = waiters.register();
        drop(g);
        let (lock, cv) = &*slot;
        let guard = lock.lock().unwrap();
        let (_guard, res) = cv
            .wait_timeout_while(guard, Duration::from_secs(2), |woken| !*woken)
            .unwrap();
        assert!(!res.timed_out(), "reader parked forever: lost wakeup (B1422 regression)");
    }
}

/// Mirrors `write`: mutate the SAME counter lock, drop it, THEN wake.
fn writer_bump(d: &EventfdData, waiters: &LossyWaitList) {
    { *d.counter.lock() += 1; }
    waiters.wake();
}

#[test]
fn concurrent_write_never_leaves_reader_parked() {
    const ITERS: usize = 4_000;
    let d = data(0, false);
    let waiters = LossyWaitList::default();

    for _ in 0..ITERS {
        let barrier = Barrier::new(2);
        thread::scope(|s| {
            let reader = s.spawn(|| { barrier.wait(); reader_once(&d, &waiters) });
            barrier.wait();
            writer_bump(&d, &waiters);
            assert_eq!(reader.join().unwrap(), 1, "counter bump must not be lost");
        });
        assert_eq!(*d.counter.lock(), 0, "counter must be drained again before next iteration");
    }
}

/// Mirrors the blocking `write`: recheck capacity and register inside ONE
/// critical section, so `reader_drain`'s drain-then-wake cannot be lost.
fn writer_once(d: &EventfdData, add: u64, waiters: &LossyWaitList) {
    loop {
        if try_add(d, add) { return; }
        let g = d.counter.lock();
        if counter::write_fits(*g, add) { drop(g); continue; }
        let slot = waiters.register();
        drop(g);
        let (lock, cv) = &*slot;
        let guard = lock.lock().unwrap();
        let (_guard, res) = cv
            .wait_timeout_while(guard, Duration::from_secs(2), |woken| !*woken)
            .unwrap();
        assert!(!res.timed_out(), "writer parked forever: lost capacity wakeup");
    }
}

#[test]
fn a_drain_never_leaves_a_full_writer_parked() {
    const ITERS: usize = 2_000;
    // One unit of headroom short of the cap: only a drain can admit the write.
    let d = data(u64::MAX - 1, false);
    let waiters = LossyWaitList::default();

    for _ in 0..ITERS {
        let barrier = Barrier::new(2);
        thread::scope(|s| {
            let writer = s.spawn(|| { barrier.wait(); writer_once(&d, 1, &waiters) });
            barrier.wait();
            let drained = try_drain(&d).expect("counter is non-zero");
            waiters.wake();
            writer.join().unwrap();
            assert!(drained >= u64::MAX - 1);
        });
        // The writer's 1 is the whole counter again; reset for the next round.
        *d.counter.lock() = u64::MAX - 1;
    }
}

#[test]
fn semaphore_mode_consumes_one_per_read() {
    let d = data(3, true);
    assert_eq!(try_drain(&d).unwrap(), 1);
    assert_eq!(try_drain(&d).unwrap(), 1);
    assert_eq!(*d.counter.lock(), 1);
}

#[test]
fn normal_mode_drains_whole_counter() {
    let d = data(5, false);
    assert_eq!(try_drain(&d).unwrap(), 5);
    assert_eq!(try_drain(&d), None);
}

// ---- the inode surface -------------------------------------------------

#[test]
fn a_read_shorter_than_eight_bytes_is_einval() {
    let inode = make_eventfd_inode(1, false);
    let mut buf = [0u8; EVENTFD_RECORD - 1];
    assert_eq!(inode.i_fop().read(&inode, 0, &mut buf), Err(VfsError::Einval));
    assert_eq!(inode.i_fop().read_nonblock(&inode, 0, &mut buf), Err(VfsError::Einval));
}

#[test]
fn a_write_of_any_length_but_eight_is_einval() {
    let inode = make_eventfd_inode(0, false);
    for len in [0usize, 1, 4, 7, 9, 16] {
        let buf = alloc::vec![0u8; len];
        assert_eq!(inode.i_fop().write_nonblock(&inode, 0, &buf), Err(VfsError::Einval),
            "len {len}: a write is exactly one u64, never a short or long count");
    }
}

#[test]
fn writing_the_sentinel_is_einval_and_leaves_the_counter_untouched() {
    let inode = make_eventfd_inode(7, false);
    assert_eq!(inode.i_fop().write_nonblock(&inode, 0, &u64::MAX.to_ne_bytes()),
        Err(VfsError::Einval));
    let mut buf = [0u8; EVENTFD_RECORD];
    assert_eq!(inode.i_fop().read_nonblock(&inode, 0, &mut buf), Ok(EVENTFD_RECORD));
    assert_eq!(u64::from_ne_bytes(buf), 7);
}

#[test]
fn a_full_counter_rejects_a_nonblocking_write_without_wrapping() {
    let inode = make_eventfd_inode(u64::MAX - 1, false);
    assert_eq!(inode.i_fop().write_nonblock(&inode, 0, &1u64.to_ne_bytes()),
        Err(VfsError::Eagain));
    let mut buf = [0u8; EVENTFD_RECORD];
    assert_eq!(inode.i_fop().read_nonblock(&inode, 0, &mut buf), Ok(EVENTFD_RECORD));
    assert_eq!(u64::from_ne_bytes(buf), u64::MAX - 1, "no wraparound to a small value");
}

#[test]
fn an_empty_counter_is_eagain_not_a_zero_byte_read() {
    let inode = make_eventfd_inode(0, false);
    let mut buf = [0u8; EVENTFD_RECORD];
    assert_eq!(inode.i_fop().read_nonblock(&inode, 0, &mut buf), Err(VfsError::Eagain));
}

#[test]
fn poll_tracks_the_counter_through_write_and_read() {
    let inode = make_eventfd_inode(0, false);
    assert_eq!(inode.i_fop().poll(&inode), vfs::POLL_OUT);
    assert_eq!(inode.i_fop().write_nonblock(&inode, 0, &2u64.to_ne_bytes()), Ok(EVENTFD_RECORD));
    assert_eq!(inode.i_fop().poll(&inode), vfs::POLL_IN | vfs::POLL_OUT);
    let mut buf = [0u8; EVENTFD_RECORD];
    assert_eq!(inode.i_fop().read_nonblock(&inode, 0, &mut buf), Ok(EVENTFD_RECORD));
    assert_eq!(u64::from_ne_bytes(buf), 2);
    assert_eq!(inode.i_fop().poll(&inode), vfs::POLL_OUT);
}

#[test]
fn a_saturated_counter_reports_no_write_capacity() {
    let inode = make_eventfd_inode(u64::MAX - 1, false);
    assert_eq!(inode.i_fop().poll(&inode), vfs::POLL_IN);
}

#[test]
fn fdinfo_renders_count_id_and_semaphore_mode() {
    let inode = make_eventfd_inode(0x2a, true);
    let mut out = Vec::new();
    inode.fdinfo_extra(&mut out);
    let text = alloc::string::String::from_utf8(out).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next().unwrap(), "eventfd-count:               2a");
    assert!(lines.next().unwrap().starts_with("eventfd-id: "));
    assert_eq!(lines.next().unwrap(), "eventfd-semaphore: 1");
    assert!(lines.next().is_none());
}

#[test]
fn fdinfo_reports_semaphore_zero_for_a_plain_eventfd() {
    let inode = make_eventfd_inode(0, false);
    let mut out = Vec::new();
    inode.fdinfo_extra(&mut out);
    let text = alloc::string::String::from_utf8(out).unwrap();
    assert!(text.contains("eventfd-semaphore: 0"), "got {text}");
    assert!(text.starts_with("eventfd-count:                0\n"), "got {text}");
}
