// kthread lifecycle — Linux `kernel/kthread.c` (`skizm.md` §2, Step 8).
//
// `spawn_kernel_thread` could only ever CREATE a kthread. There was no way to
// ask one to stop and no way to stand one down temporarily, so every kthread in
// the tree loops forever and a CPU cannot be offlined without abandoning its
// per-CPU threads.
//
// Linux's model, kept exactly, because the alternative is worse: nothing here
// forcibly terminates a thread. `kthread_stop` REQUESTS, and the thread's own
// loop observes it at a point where it holds no lock and owns no in-flight I/O.
// Killing a kthread asynchronously would strand whatever it was holding.
//
// The loop shape this expects:
//
//     while !kthread::should_stop(me) {
//         kthread::park_if_requested(me);   // stand down for hotplug
//         ...work...
//     }

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use sync::{KthreadPark as ParkGateClass, Spinlock};

use crate::Task;
use super::WaitList;

/// Parked kthreads wait here; `unpark` wakes them.
static PARK_WAIT: WaitList = WaitList::new();

/// Gate serializing `park_if_requested`'s check-then-enqueue against
/// `unpark`/`stop`'s clear-then-wake (B1427). Without it: the kthread reads
/// `kthread_park == true` (still requested), then before it registers on
/// `PARK_WAIT`, `unpark` on another CPU clears the flag and calls
/// `wake_all()` — finding an EMPTY wait list (the kthread hasn't parked yet)
/// and `try_to_wake_up` — a no-op, since the kthread's state is still
/// Runnable, not Sleeping (ttwu only transitions Sleeping→Runnable). Both
/// wake attempts are silently lost, then the kthread parks and sleeps
/// forever. Holding this gate across the check + `PARK_WAIT.park()` on the
/// kthread side, and across the flag clear + `wake_all()` on the
/// unpark/stop side, forces one side to fully complete before the other
/// starts — same shape as `sched::live::mutex::Mutex::lock`.
static PARK_GATE: Spinlock<(), ParkGateClass> = Spinlock::new(());

/// Linux `kthread_should_stop`: has someone asked this thread to exit?
/// The thread polls this at a point of its own choosing.
/// # C: O(1)
pub fn should_stop(me: &Task) -> bool { me.kthread_stop.load(Ordering::Acquire) }

/// Linux `kthread_stop`: ask `task` to exit and wake it so it notices.
///
/// Returns immediately — this is a request, not a join. A caller that needs to
/// know the thread is gone waits on the thread's own completion signal, exactly
/// as Linux callers do when `kthread_stop`'s return value is not enough.
/// # C: O(1)
pub fn stop(task: &Arc<Task>) {
    task.kthread_stop.store(true, Ordering::Release);
    // Also clear any park request: a thread asked to stop must not sit parked
    // waiting for an unpark that will never come.
    {
        let _g = PARK_GATE.lock();
        task.kthread_park.store(false, Ordering::Release);
        PARK_WAIT.wake_all();
    }
    // SAFETY: process-context caller; waking a task that may be parked on any
    // list is the normal ttwu path and takes no lock the caller holds.
    unsafe { let _ = super::try_to_wake_up(Arc::clone(task)); }
}

/// Linux `kthread_park`: ask `task` to stand down at its next check.
///
/// Used by CPU hotplug — a per-CPU kthread must leave its CPU without exiting,
/// so it can resume when the CPU comes back.
/// # C: O(1)
pub fn park(task: &Arc<Task>) {
    task.kthread_park.store(true, Ordering::Release);
}

/// Linux `kthread_unpark`: release a parked thread.
/// # C: O(1) + wake
pub fn unpark(task: &Arc<Task>) {
    {
        let _g = PARK_GATE.lock();
        task.kthread_park.store(false, Ordering::Release);
        task.kthread_parked.store(false, Ordering::Release);
        PARK_WAIT.wake_all();
    }
    // SAFETY: process-context caller; ordinary wake of a parked kthread.
    unsafe { let _ = super::try_to_wake_up(Arc::clone(task)); }
}

/// Has `task` observed a park request and actually parked? Lets a hotplug
/// caller wait for the thread to be off its CPU rather than merely asked.
/// # C: O(1)
pub fn is_parked(task: &Task) -> bool { task.kthread_parked.load(Ordering::Acquire) }

/// Called BY a kthread at a safe point: if a park was requested, sleep until
/// unparked (or until a stop request arrives). Returns immediately otherwise.
///
/// # SAFETY: caller is the running kthread, holds no lock, and is at a point
/// where sleeping is legal — the same contract every `WaitList::park` site has.
/// # C: O(1) when not parking
/// # Sleeps: while parked
pub unsafe fn park_if_requested(me: &Task) {
    loop {
        let gate = PARK_GATE.lock();
        if !(me.kthread_park.load(Ordering::Acquire) && !should_stop(me)) {
            break;
        }
        me.kthread_parked.store(true, Ordering::Release);
        // SAFETY: per this fn's contract — running kthread, no lock held
        // once `gate` drops below; the matching schedule() yields
        // immediately per the WaitList contract. Registering under `gate`
        // (held since the check above) closes the race documented on
        // `PARK_GATE`.
        unsafe { PARK_WAIT.park(); }
        drop(gate);
        // SAFETY: parked on PARK_WAIT holding no lock.
        unsafe { super::schedule(); }
    }
    me.kthread_parked.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{SchedClass, Task};

    fn kthread(tid: u32) -> Arc<Task> {
        Arc::new(Task::new(tid, "kth", SchedClass::Normal { weight: 1024 }))
    }

    #[test]
    fn a_fresh_kthread_is_neither_stopping_nor_parked() {
        let t = kthread(7001);
        assert!(!should_stop(&t));
        assert!(!is_parked(&t));
    }

    #[test]
    fn stop_is_observable_by_the_thread() {
        let t = kthread(7002);
        stop(&t);
        assert!(should_stop(&t), "the thread's own loop must see the request");
    }

    #[test]
    fn stop_cancels_a_pending_park() {
        // A thread asked to stop must not sit parked waiting for an unpark that
        // is never coming — that would hang shutdown.
        let t = kthread(7003);
        park(&t);
        assert!(t.kthread_park.load(Ordering::Acquire));
        stop(&t);
        assert!(!t.kthread_park.load(Ordering::Acquire), "stop must clear the park request");
        assert!(should_stop(&t));
    }

    #[test]
    fn unpark_clears_both_the_request_and_the_parked_state() {
        let t = kthread(7004);
        park(&t);
        t.kthread_parked.store(true, Ordering::Release);
        assert!(is_parked(&t));
        unpark(&t);
        assert!(!t.kthread_park.load(Ordering::Acquire));
        assert!(!is_parked(&t), "a released thread must not still report parked");
    }
}

// B1427 regression: `park_if_requested` used to check `kthread_park` and
// then register on `PARK_WAIT` with no lock spanning the two. `unpark`'s
// clear-request + `wake_all()` could land in that gap and be lost — the real
// scheduler's `try_to_wake_up` fallback does not rescue it either, since the
// kthread's task state is still Runnable (not yet Sleeping) at that point,
// and `ttwu` only transitions Sleeping→Runnable.
//
// `sched::live` has no runqueue under a hosted `cargo test` build, so the
// real `WaitList::park`/`schedule` are unreachable here (same gap
// `pipe/eventfd.rs`'s B1422 test and `drv-virtio-blk`'s B1426 test hit).
// This drives real OS threads against a `LossyWaitList` stand-in — a wake is
// dropped if nobody is registered yet, unlike `std::thread::park`/`unpark`
// whose token persists regardless of call order and would validate nothing —
// exercising the SAME gate-then-check-then-enqueue shape `PARK_GATE` now
// enforces.
#[cfg(test)]
mod race_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, Condvar, Mutex};
    use std::thread;
    use std::time::Duration;

    type WakeSlot = Arc<(Mutex<bool>, Condvar)>;

    #[derive(Default)]
    struct LossyWaitList {
        slot: Mutex<Option<WakeSlot>>,
    }
    impl LossyWaitList {
        fn register(&self) -> WakeSlot {
            let slot = Arc::new((Mutex::new(false), Condvar::new()));
            *self.slot.lock().unwrap() = Some(slot.clone());
            slot
        }
        fn wake_all(&self) {
            if let Some(slot) = self.slot.lock().unwrap().take() {
                *slot.0.lock().unwrap() = true;
                slot.1.notify_all();
            }
        }
    }

    /// Mirrors the FIXED `park_if_requested`: one gate covers the
    /// "still requested?" check AND the wait-list registration, dropped only
    /// after the enqueue — before the actual sleep.
    fn park_if_requested_fixed(park_requested: &AtomicBool, gate: &Mutex<()>, waiters: &LossyWaitList) {
        loop {
            let g = gate.lock().unwrap();
            if !park_requested.load(Ordering::Acquire) {
                drop(g);
                return;
            }
            let mine = waiters.register();
            drop(g);
            let (lock, cv) = &*mine;
            let guard = lock.lock().unwrap();
            let (_guard, res) = cv
                .wait_timeout_while(guard, Duration::from_secs(2), |woken| !*woken)
                .unwrap();
            assert!(!res.timed_out(), "kthread parked forever: lost wakeup (B1427 regression)");
        }
    }

    /// Mirrors the FIXED `unpark`: mutate the request flag AND call
    /// `wake_all()` under the SAME gate `park_if_requested_fixed` holds
    /// across its check + register.
    fn unpark_fixed(park_requested: &AtomicBool, gate: &Mutex<()>, waiters: &LossyWaitList) {
        let g = gate.lock().unwrap();
        park_requested.store(false, Ordering::Release);
        waiters.wake_all();
        drop(g);
    }

    /// The OLD buggy shape: check, THEN register, THEN unconditionally sleep
    /// — no gate spanning the two, no post-registration recheck. Two barriers
    /// force the unpark's clear+wake to land strictly between the check and
    /// the registration, so it deterministically lands on an empty list —
    /// proving the `LossyWaitList` stand-in reproduces the B1427 class of
    /// bug, so the fixed-shape test below catching it means something.
    fn park_if_requested_buggy(
        park_requested: &AtomicBool, waiters: &LossyWaitList, poll_done: &Barrier, wake_done: &Barrier,
    ) {
        if !park_requested.load(Ordering::Acquire) { return; }
        poll_done.wait();
        wake_done.wait();
        // Register AFTER unpark's clear+wake already ran and found the list
        // empty — mirrors the pre-fix `PARK_WAIT.park()` with no lock held
        // across the check above.
        let mine = waiters.register();
        let (lock, cv) = &*mine;
        let guard = lock.lock().unwrap();
        let (_guard, res) = cv
            .wait_timeout_while(guard, Duration::from_millis(200), |woken| !*woken)
            .unwrap();
        assert!(res.timed_out(), "harness sanity: the buggy shape was expected to lose this wakeup");
    }

    fn unpark_buggy(park_requested: &AtomicBool, waiters: &LossyWaitList) {
        park_requested.store(false, Ordering::Release);
        waiters.wake_all();
    }

    #[test]
    fn buggy_check_then_park_can_lose_a_wakeup() {
        let park_requested = AtomicBool::new(true);
        let waiters = LossyWaitList::default();
        let poll_done = Barrier::new(2);
        let wake_done = Barrier::new(2);
        thread::scope(|s| {
            s.spawn(|| park_if_requested_buggy(&park_requested, &waiters, &poll_done, &wake_done));
            poll_done.wait();
            // Runs the clear+wake strictly between the kthread's check and
            // its registration: the wake lands on an empty list and is
            // dropped.
            unpark_buggy(&park_requested, &waiters);
            wake_done.wait();
        });
    }

    #[test]
    fn concurrent_unpark_never_leaves_kthread_parked() {
        const ITERS: usize = 4_000;
        for _ in 0..ITERS {
            let park_requested = AtomicBool::new(true);
            let gate: Mutex<()> = Mutex::new(());
            let waiters = LossyWaitList::default();
            let barrier = Barrier::new(2);
            thread::scope(|s| {
                let kt = s.spawn(|| {
                    barrier.wait();
                    park_if_requested_fixed(&park_requested, &gate, &waiters);
                });
                barrier.wait();
                unpark_fixed(&park_requested, &gate, &waiters);
                kt.join().expect("kthread thread must finish (no lost wakeup)");
            });
            assert!(!park_requested.load(Ordering::Acquire));
        }
    }
}
