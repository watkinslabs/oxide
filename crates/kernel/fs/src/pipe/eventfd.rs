// Eventfd (`24§3`, Linux eventfd(2)) — counter-based blocking primitive
// backing `sys_eventfd2`. Split out of `pipe.rs` (`08§7` file-length cap):
// the counter is unrelated to the byte-ring FIFO/anon-pipe core in
// `ring.rs`; keeping it here keeps `pipe.rs` a manifest for the FIFO/
// anon-pipe surface.
//
// B1422: the counter lives behind `EventfdGate` (a `Spinlock<u64, _>`), not a
// bare `AtomicU64` CASed lock-free. A blocking `read` that found the counter
// 0 used to check-then-`park()` with no lock held across both steps, while
// `write` mutated the counter and called `wake_all()` lock-free — the
// classic lost wakeup: if the write's CAS+wake_all landed between the read
// seeing zero and the read's `park()`, the wait list was still empty, the
// wake was dropped, and the reader parked forever. Now "counter==0 → enqueue
// on read_waiters" is ONE critical section over `EventfdGate`, and `write`
// takes the SAME lock to bump the counter before it wakes — same shape as
// `sched::live::Mutex::lock` / `net::unix_sock::listener::arm_accept_wait`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use sync::Spinlock;
use vfs::{FileType, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, PollSubscribers, default_inode_ops, mk_mode};

use super::WaitList;

/// `Inode`-backed eventfd counter per `24§3` + Linux eventfd(2).
/// Read drains the counter to a u64; write adds to it. A BLOCKING read on a
/// zero counter PARKS on `read_waiters` until a write makes it non-zero (Linux
/// eventfd(2) blocks; a non-blocking read returns EAGAIN — NEVER EINVAL). The
/// counter lives in `i_private`.
pub struct EventfdData {
    counter: Spinlock<u64, EventfdGate>,
    semaphore: bool,
    /// Tasks parked in a blocking `read` that found the counter 0; woken by
    /// `write`. (No blocking-write parking: a u64 counter effectively never
    /// fills in these control-fd uses.)
    read_waiters: WaitList,
}

/// Gates an eventfd's counter (`06§3.6`). Held only to decide "read now or
/// park" — the same shape as `sched::live::Mutex`'s `MutexGate`: the park
/// enqueues on `read_waiters` (`TaskList`, rank 100) while holding this, so it
/// ranks strictly below that, and is never held across `schedule()` itself.
struct EventfdGate;
impl sync::LockClass for EventfdGate { fn rank() -> u16 { 94 } fn name() -> &'static str { "EventfdGate" } }

mod ids {
    pub(crate) const EVENTFD_INO_BASE: u64 = 0x4000_0000;
}

static NEXT_EVENTFD_INO: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(ids::EVENTFD_INO_BASE);

/// `make_eventfd_inode(initial, semaphore)` — a Fifo pseudo-inode whose counter
/// drains on read and accumulates on write. # C: O(1)
pub fn make_eventfd_inode(initial: u64, semaphore: bool) -> InodeRef {
    let ino = NEXT_EVENTFD_INO.fetch_add(1, Ordering::Relaxed);
    InodeBuilder::new(ino, mk_mode(FileType::Fifo, 0), default_inode_ops(), Arc::new(EventfdFileOps))
        .poll_subs(PollSubscribers::new())
        .private(Arc::new(EventfdData {
            counter: Spinlock::new(initial),
            semaphore,
            read_waiters: WaitList::new(),
        }))
        .build()
}

/// `i_fop` for an eventfd inode. # C: O(1)
struct EventfdFileOps;
impl FileOps for EventfdFileOps {
    /// POLLIN when the counter is nonzero (read won't block); POLLOUT
    /// when it can still accept a write (< u64::MAX-1). Default
    /// always-ready poll busy-looped systemd's sd-event epoll — see
    /// signalfd::poll.
    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let v = match inode.private::<EventfdData>() { Some(d) => *d.counter.lock(), None => return 0 };
        let mut m = 0;
        if v > 0 { m |= vfs::POLL_IN; }
        if v < u64::MAX - 1 { m |= vfs::POLL_OUT; }
        m
    }
    /// BLOCKING read (Linux eventfd(2)): drain the counter; if it is 0, PARK
    /// until a write makes it non-zero (interruptible by a deliverable signal →
    /// EINTR). NEVER EINVAL on an empty counter — that broke systemd's
    /// `setup_private_users` `(sd-userns)` helper, whose blocking
    /// `read(unshare_ready_fd)` barrier got EINVAL and reported it to the
    /// executor → EXIT_USER(217) for every PrivateUsers= unit (upower, …).
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(VfsError::Einval); }
        let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        loop {
            if let Some(v) = try_drain(d) {
                buf[..8].copy_from_slice(&v.to_ne_bytes());
                if let Some(s) = inode.poll_subscribers() { s.notify(); }
                return Ok(8);
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                // ONE critical section covers "counter is zero" and the park
                // enqueue: `write` takes this SAME counter lock to bump the
                // counter before it wakes (see `write` below), so a
                // concurrent bump+wake_all can never land between "we saw
                // zero" and "we're on the wait list" (B1422).
                let g = d.counter.lock();
                if *g != 0 { drop(g); continue; }
                // Linux `eventfd_read` (`fs/eventfd.c:232`): `-ERESTARTSYS`.
                if sched::live::deliverable_signals_self() != 0 {
                    drop(g);
                    return Err(VfsError::Erestartsys);
                }
                // SAFETY: running task; preempt-off; park bumps the Arc +
                // marks Sleeping while we still hold the counter lock, so a
                // racing write's bump+wake_all cannot land between this
                // recheck and our enqueue.
                unsafe { d.read_waiters.park(); }
                drop(g);
                // SAFETY: process ctx; runqueue installed; preempt-off;
                // Sleeping so schedule won't re-enqueue until a write wakes
                // us. Counter lock already dropped above, before schedule.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }
    /// Non-blocking read (O_NONBLOCK): EAGAIN on an empty counter (Linux), not
    /// EINVAL and not a park.
    fn read_nonblock(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(VfsError::Einval); }
        let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        match try_drain(d) {
            Some(v) => {
                buf[..8].copy_from_slice(&v.to_ne_bytes());
                if let Some(s) = inode.poll_subscribers() { s.notify(); }
                Ok(8)
            }
            None => Err(VfsError::Eagain),
        }
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        if buf.len() != 8 { return Err(VfsError::Einval); }
        let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        let mut a = [0u8; 8];
        a.copy_from_slice(buf);
        let add = u64::from_ne_bytes(a);
        if add == u64::MAX { return Err(VfsError::Einval); }
        {
            let mut g = d.counter.lock();
            if u64::MAX - *g <= add { return Err(VfsError::Eagain); }
            *g += add;
        }
        // Wake AFTER dropping the counter lock (matches `Mutex::unlock`): the
        // woken reader's first act is to take the SAME lock, so waking under
        // it would just make it spin on us. Also pokes poll/epoll waiters
        // (sd-event drives eventfds via epoll_wait).
        d.read_waiters.wake_all();
        if let Some(s) = inode.poll_subscribers() { s.notify(); }
        Ok(8)
    }
}

/// Drain the counter without blocking, under the gate. `None` when zero
/// (caller EAGAINs or parks). Semaphore mode consumes 1 per read; normal mode
/// swaps the whole counter to 0. # C: O(1)
fn try_drain(d: &EventfdData) -> Option<u64> {
    let mut g = d.counter.lock();
    if *g == 0 { return None; }
    if d.semaphore {
        *g -= 1;
        Some(1)
    } else {
        let v = *g;
        *g = 0;
        Some(v)
    }
}

// B1422 — lost-wakeup regression test for the counter read/write path. As in
// `pipe/ring.rs`'s equivalent test, `sched::live` has no runqueue under a
// hosted `cargo test` build, so `WaitList::park`/`schedule` are unreachable
// there; this drives real OS threads against the SAME `EventfdGate` lock
// production code uses, with a wait-list stand-in as lossy as the real one
// (a wake is dropped if nobody is registered yet — unlike
// `std::thread::park`/`unpark`, whose token persists regardless of call
// order and would validate nothing about the fix).
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Barrier, Condvar, Mutex};
    use std::thread;
    use std::time::Duration;

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
            // ONE critical section over `d.counter`: recheck, and if still
            // zero, register WHILE STILL HOLDING the lock (mirrors `read`'s
            // `d.counter.lock()` gate held across the recheck + park
            // enqueue) before dropping it.
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
        let d = EventfdData { counter: Spinlock::new(0), semaphore: false, read_waiters: WaitList::new() };
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

    #[test]
    fn semaphore_mode_consumes_one_per_read() {
        let d = EventfdData { counter: Spinlock::new(3), semaphore: true, read_waiters: WaitList::new() };
        assert_eq!(try_drain(&d).unwrap(), 1);
        assert_eq!(try_drain(&d).unwrap(), 1);
        assert_eq!(*d.counter.lock(), 1);
    }

    #[test]
    fn normal_mode_drains_whole_counter() {
        let d = EventfdData { counter: Spinlock::new(5), semaphore: false, read_waiters: WaitList::new() };
        assert_eq!(try_drain(&d).unwrap(), 5);
        assert_eq!(try_drain(&d), None);
    }
}
