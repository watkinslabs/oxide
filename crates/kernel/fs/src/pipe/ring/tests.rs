// B1422 — lost-wakeup regression test for `read_blocking`. `sched::live`
// (the real scheduler) does not exist under a hosted `cargo test` build (no
// runqueue is ever installed, so `WaitList::park`/`schedule` degrade to
// no-ops — see the crate-level `WaitList` hosted stand-in in `pipe.rs`), so
// this cannot drive the exact production park/wake call. Instead it drives
// real OS threads against the SAME ring lock (`PipeData.buf`) production
// code uses, with a wait-list stand-in that is deliberately AS LOSSY as the
// real one: a wake is silently dropped if nobody is registered yet. Unlike
// `std::thread::park`/`unpark` (whose token persists regardless of call
// order, which would validate nothing here), this reproduces the exact
// failure shape: if "check empty" and "register as parked" are not one
// critical section with the writer's "mutate, drop, wake", the wake can be
// dropped and the reader hangs. `reader_once` below mirrors the FIXED
// `read_blocking` shape line for line; `writer_push` mirrors
// `write_iter_blocking`'s mutate-under-lock/drop/wake.
//
// B1681 adds the ring-growth and capacity coverage: the ring used to be a
// fixed 4 KiB inline array, which silently truncated every core dump.

use super::*;
use std::sync::{Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

#[test]
fn a_core_dump_wait_stops_for_a_kill_or_freezer_but_not_its_delivered_signal() {
    assert!(!write_wait_aborted(WriteAbort::OnFatalKill, true, false, false),
        "the signal being dumped must not discard its own core");
    assert!(write_wait_aborted(WriteAbort::OnFatalKill, false, true, false));
    assert!(write_wait_aborted(WriteAbort::OnFatalKill, false, false, true));
    assert!(write_wait_aborted(WriteAbort::OnDeliverableSignal, true, false, false));
}

/// Lossy hosted wait-list stand-in: `wake` is a no-op unless a reader is
/// currently registered — exactly `WaitList::wake_all` finding an empty
/// list.
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

/// Mirrors the FIXED `read_blocking`: one critical section over
/// `pd.buf` covers "is there data" and "register as parked" so
/// `writer_push`'s mutate-then-wake can never land in the gap.
fn reader_once(pd: &PipeData, waiters: &LossyWaitList) -> usize {
    loop {
        let mut g = pd.buf.lock();
        if g.len != 0 {
            let mut tmp = [0u8; 1];
            return PipeData::drain_locked(&mut g, &mut tmp);
        }
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

/// Mirrors `write_iter_blocking`/`try_fill_iter`: mutate the SAME ring
/// lock, drop it, THEN wake.
fn writer_push(pd: &PipeData, waiters: &LossyWaitList) {
    { pd.buf.lock().push(b'x', false, false); }
    waiters.wake();
}

#[test]
fn concurrent_write_never_leaves_reader_parked() {
    const ITERS: usize = 4_000;
    let pd = PipeData::new(1);
    pd.writers.store(1, Ordering::Release);
    pd.readers.store(1, Ordering::Release);
    let waiters = LossyWaitList::default();

    for _ in 0..ITERS {
        let barrier = Barrier::new(2);
        thread::scope(|s| {
            let reader = s.spawn(|| { barrier.wait(); reader_once(&pd, &waiters) });
            barrier.wait();
            writer_push(&pd, &waiters);
            assert_eq!(reader.join().unwrap(), 1, "byte must not be lost or duplicated");
        });
        // Ring must be empty again before the next iteration's push.
        assert_eq!(pd.buf.lock().len, 0);
    }
}

/// Fill a ring one byte at a time; report how many it accepted.
fn fill_bytes(pd: &PipeData, n: usize) -> usize {
    let mut g = pd.buf.lock();
    let mut written = 0;
    for i in 0..n {
        if !g.push((i % 251) as u8, false, false) { break; }
        written += 1;
    }
    written
}

#[test]
fn a_fresh_ring_holds_the_default_pipe_size_not_one_page() {
    let pd = PipeData::new(1);
    assert_eq!(pd.capacity(), PIPE_DEF_SIZE);
    assert_eq!(fill_bytes(&pd, PIPE_DEF_SIZE + 1024), PIPE_DEF_SIZE,
        "a ring capped at one page truncates every core dump");
}

#[test]
fn the_backing_store_is_allocated_on_demand_not_up_front() {
    let pd = PipeData::new(1);
    assert_eq!(pd.buf.lock().data.len(), 0, "an unused pipe must not reserve its ceiling");
    fill_bytes(&pd, 1);
    assert_eq!(pd.buf.lock().data.len(), PIPE_GROW_STEP);
    fill_bytes(&pd, PIPE_GROW_STEP);
    assert_eq!(pd.buf.lock().data.len(), 2 * PIPE_GROW_STEP);
}

#[test]
fn growth_across_a_wrapped_ring_preserves_byte_order() {
    let pd = PipeData::new(1);
    // Fill the first unit, drain most of it so head moves off zero, then
    // write past the allocation so the ring both wraps and grows.
    assert_eq!(fill_bytes(&pd, PIPE_GROW_STEP), PIPE_GROW_STEP);
    let mut sink = alloc::vec![0u8; PIPE_GROW_STEP - 8];
    {
        let mut g = pd.buf.lock();
        assert_eq!(PipeData::drain_locked(&mut g, &mut sink), PIPE_GROW_STEP - 8);
        assert_ne!(g.head, 0, "the ring must be wrapped for this to test anything");
    }
    // Write past the current allocation so the ring has to grow while wrapped.
    let more = 2 * PIPE_GROW_STEP;
    assert_eq!(fill_bytes(&pd, more), more);
    assert!(pd.buf.lock().data.len() >= 8 + more);
    let mut out = alloc::vec![0u8; 8 + more];
    let n = { let mut g = pd.buf.lock(); PipeData::drain_locked(&mut g, &mut out) };
    assert_eq!(n, 8 + more);
    // The 8 bytes that survived the drain come out first, in order, followed by
    // every byte of the second fill — growth must not reorder or drop any.
    let survivors: Vec<u8> = (PIPE_GROW_STEP - 8..PIPE_GROW_STEP).map(|i| (i % 251) as u8).collect();
    assert_eq!(&out[..8], &survivors[..]);
    let fresh: Vec<u8> = (0..more).map(|i| (i % 251) as u8).collect();
    assert_eq!(&out[8..], &fresh[..]);
}

#[test]
fn a_write_up_to_pipe_buf_is_all_or_nothing() {
    let pd = PipeData::new(1);
    pd.readers.store(1, Ordering::Release);
    pd.writers.store(1, Ordering::Release);
    // Leave less than PIPE_BUF of room.
    let head = alloc::vec![0u8; PIPE_DEF_SIZE - (PIPE_BUF - 1)];
    assert_eq!(pd.write_iter_nb(None, &[&head], false).unwrap(), head.len());
    // A PIPE_BUF-sized write cannot be split, so it places nothing at all.
    let atomic = alloc::vec![1u8; PIPE_BUF];
    assert_eq!(pd.write_iter_nb(None, &[&atomic], false), Err(VfsError::Eagain));
    assert_eq!(pd.buf.lock().len, head.len(), "an atomic write must not partially land");
    // A write LARGER than PIPE_BUF carries no such guarantee and may be short.
    let big = alloc::vec![2u8; PIPE_BUF + 1];
    assert_eq!(pd.write_iter_nb(None, &[&big], false).unwrap(), PIPE_BUF - 1);
}

#[test]
fn a_write_that_exactly_fills_the_remaining_room_is_admitted() {
    let pd = PipeData::new(1);
    pd.readers.store(1, Ordering::Release);
    pd.writers.store(1, Ordering::Release);
    let head = alloc::vec![0u8; PIPE_DEF_SIZE - PIPE_BUF];
    assert_eq!(pd.write_iter_nb(None, &[&head], false).unwrap(), head.len());
    let atomic = alloc::vec![1u8; PIPE_BUF];
    assert_eq!(pd.write_iter_nb(None, &[&atomic], false).unwrap(), PIPE_BUF);
    assert_eq!(pd.buf.lock().len, PIPE_DEF_SIZE);
}

#[test]
fn pipe_buf_atomicity_still_binds_after_the_pipe_is_grown() {
    let inode = make_pipe_inode();
    let pd = pipe_data(&inode).unwrap();
    pd.readers.store(1, Ordering::Release);
    pd.writers.store(1, Ordering::Release);
    let grown = set_pipe_size(&inode, 4 * PIPE_DEF_SIZE).unwrap();
    assert!(grown > PIPE_DEF_SIZE, "the resize must have raised the ceiling");

    // One byte short of the room an atomic write needs, at the NEW capacity.
    let head = alloc::vec![0u8; grown - (PIPE_BUF - 1)];
    assert_eq!(pd.write_iter_nb(None, &[&head], false).unwrap(), head.len());
    let atomic = alloc::vec![1u8; PIPE_BUF];
    assert_eq!(pd.write_iter_nb(None, &[&atomic], false), Err(VfsError::Eagain));
    assert_eq!(pd.buf.lock().len, head.len(), "a resize must not weaken atomicity");
    // The atomic unit is PIPE_BUF, not the capacity: a write past PIPE_BUF is
    // still admitted short even though it would fit the grown ring outright.
    let big = alloc::vec![2u8; PIPE_BUF + 1];
    assert_eq!(pd.write_iter_nb(None, &[&big], false).unwrap(), PIPE_BUF - 1,
        "a resize must not widen the atomic unit to the capacity");
    assert_eq!(pd.buf.lock().len, grown);
}

#[test]
fn resizing_reports_at_least_what_was_asked_for_and_refuses_the_ceiling() {
    let inode = make_pipe_inode();
    assert_eq!(pipe_size(&inode), Some(PIPE_DEF_SIZE));
    assert_eq!(set_pipe_size(&inode, PIPE_BUF + 1), Ok(2 * PIPE_GROW_STEP));
    assert_eq!(pipe_size(&inode), Some(2 * PIPE_GROW_STEP));
    assert_eq!(set_pipe_size(&inode, PIPE_MAX_SIZE), Ok(PIPE_MAX_SIZE));
    assert_eq!(set_pipe_size(&inode, PIPE_MAX_SIZE + 1), Err(VfsError::Eperm));
    // A pipe never shrinks below one allocation unit.
    assert_eq!(set_pipe_size(&inode, 1), Ok(PIPE_GROW_STEP));
}

#[test]
fn a_pipe_cannot_shrink_below_the_bytes_still_queued() {
    let inode = make_pipe_inode();
    let pd = pipe_data(&inode).unwrap();
    assert_eq!(fill_bytes(pd, 3 * PIPE_GROW_STEP), 3 * PIPE_GROW_STEP);
    assert_eq!(set_pipe_size(&inode, PIPE_GROW_STEP), Err(VfsError::Ebusy));
    assert_eq!(pipe_size(&inode), Some(PIPE_DEF_SIZE), "a refused resize changes nothing");
}

#[test]
fn a_shrunken_capacity_stops_accepting_bytes_at_the_new_ceiling() {
    let inode = make_pipe_inode();
    let pd = pipe_data(&inode).unwrap();
    assert_eq!(fill_bytes(pd, 2 * PIPE_GROW_STEP), 2 * PIPE_GROW_STEP);
    assert_eq!(set_pipe_size(&inode, 2 * PIPE_GROW_STEP), Ok(2 * PIPE_GROW_STEP));
    assert_eq!(fill_bytes(pd, 1), 0);
    // Draining one byte frees exactly one slot.
    let mut one = [0u8; 1];
    { let mut g = pd.buf.lock(); assert_eq!(PipeData::drain_locked(&mut g, &mut one), 1); }
    assert_eq!(fill_bytes(pd, 4), 1);
}

#[test]
fn poll_reports_writable_only_while_room_remains() {
    let inode = make_pipe_inode();
    let pd = pipe_data(&inode).unwrap();
    pd.readers.store(1, Ordering::Release);
    pd.writers.store(1, Ordering::Release);
    assert!(pd.poll_mask() & vfs::POLL_OUT != 0);
    assert_eq!(fill_bytes(pd, PIPE_DEF_SIZE), PIPE_DEF_SIZE);
    assert_eq!(pd.poll_mask() & vfs::POLL_OUT, 0, "a full pipe is not writable");
    assert!(pd.poll_mask() & vfs::POLL_IN != 0);
}
