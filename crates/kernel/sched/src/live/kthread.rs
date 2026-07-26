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

use crate::Task;
use super::WaitList;

/// Parked kthreads wait here; `unpark` wakes them.
static PARK_WAIT: WaitList = WaitList::new();

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
    task.kthread_park.store(false, Ordering::Release);
    PARK_WAIT.wake_all();
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
    task.kthread_park.store(false, Ordering::Release);
    task.kthread_parked.store(false, Ordering::Release);
    PARK_WAIT.wake_all();
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
    while me.kthread_park.load(Ordering::Acquire) && !should_stop(me) {
        me.kthread_parked.store(true, Ordering::Release);
        // SAFETY: per this fn's contract — running kthread, no lock held; the
        // matching schedule() yields immediately per the WaitList contract.
        unsafe { PARK_WAIT.park(); super::schedule(); }
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
