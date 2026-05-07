// Generic FIFO wait list — companion to the per-subsystem WAITERS
// pattern in `zombies.rs`. Subsystems that need blocking semantics
// (SysV sem/msg, POSIX MQ, futex) instantiate one `WaitList` per
// resource and call `park()` to sleep, `wake_one()` / `wake_all()`
// from the corresponding wake site.
//
// Lock-ordering contract:
//   - Caller holds the resource lock (e.g. SemSet.vals) when
//     calling park(); park() acquires the wait list's internal
//     lock briefly to push, then returns. Caller drops resource
//     lock then calls schedule().
//   - Wakers (commit path) drop the resource lock BEFORE calling
//     wake_one/wake_all so the wait list lock is never nested
//     under the resource lock from the publisher side.
//
// This is the standard "lock-resource → push-to-wait → drop-
// resource → schedule" pattern. Wakeups can race with park
// without losing wake events because publishers always wake
// AFTER mutating the resource: a waiter that acquired the
// resource lock and saw the unmet condition will be visible on
// the wait list before the publisher can wake (publisher needs
// the resource lock to mutate, which the waiter already holds
// when pushing to the list).

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sched::{Task, TaskState};
use sync::{Spinlock, TaskList as WaitClass};

/// FIFO wait list. Holds strong refs to parked tasks; drops them
/// on wake (after enqueueing on the runqueue).
pub struct WaitList {
    waiters: Spinlock<Vec<Arc<Task>>, WaitClass>,
}

impl WaitList {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { waiters: Spinlock::new(Vec::new()) }
    }

    /// Park the running task on this list, marking it Sleeping.
    /// Caller MUST call `crate::sched::schedule()` immediately
    /// after to yield. Caller MUST NOT hold any lock that a waker
    /// also needs to take (otherwise the waker deadlocks while
    /// we sleep).
    /// # SAFETY: caller is the running task on this CPU; preempt-
    /// off; runqueue installed via `install_global`. The `Arc`
    /// strong-count bump matches `Arc::from_raw` so the count
    /// stays balanced across park/wake.
    /// # C: O(1)
    /// # Lk: WaitList.waiters (TaskList class)
    pub unsafe fn park(&self) {
        let rq = match crate::sched::global() { Some(r) => r, None => return };
        let raw = rq.current.load(Ordering::Acquire);
        if raw.is_null() { return; }
        // SAFETY: rq.current is non-null after install_global; bump strong count to materialise an Arc the wait list can hold across schedule.
        unsafe { Arc::increment_strong_count(raw); }
        // SAFETY: matching Arc::from_raw consumes the bumped ref.
        let arc = unsafe { Arc::from_raw(raw) };
        arc.set_state(TaskState::Sleeping);
        self.waiters.lock().push(arc);
    }

    /// Wake the longest-waiting task on this list (FIFO). No-op
    /// if empty. Sets state Runnable, lifts vruntime to the CFS
    /// minimum, enqueues on the runqueue, sets need_resched.
    /// # C: O(1)
    /// # Lk: WaitList.waiters then runqueue.inner
    pub fn wake_one(&self) {
        let popped: Option<Arc<Task>> = {
            let mut g = self.waiters.lock();
            if g.is_empty() { None } else { Some(g.remove(0)) }
        };
        if let Some(t) = popped { Self::enqueue_runnable(t); }
    }

    /// Wake every task on this list. Used by IPC commit paths
    /// where multiple waiters may now succeed (e.g. semop commit
    /// raises a value — different waiters needed different
    /// magnitudes).
    /// # C: O(N_waiters)
    /// # Lk: WaitList.waiters then runqueue.inner (per task)
    pub fn wake_all(&self) {
        let drained: Vec<Arc<Task>> = {
            let mut g = self.waiters.lock();
            if g.is_empty() { return; }
            g.drain(..).collect()
        };
        for t in drained { Self::enqueue_runnable(t); }
    }

    /// True if any task is currently parked.
    /// # C: O(1)
    pub fn has_waiters(&self) -> bool {
        !self.waiters.lock().is_empty()
    }

    /// Internal helper: transition a popped task to Runnable and
    /// enqueue on the global runqueue.
    fn enqueue_runnable(t: Arc<Task>) {
        let rq = match crate::sched::global() { Some(r) => r, None => return };
        let mut inner = rq.inner.lock();
        t.set_state(TaskState::Runnable);
        t.lift_vruntime(inner.cfs.min_vruntime());
        inner.enqueue(t);
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
        crate::preempt::set_need_resched();
    }
}

impl Default for WaitList {
    fn default() -> Self { Self::new() }
}
