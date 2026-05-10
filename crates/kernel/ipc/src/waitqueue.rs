// Wait queue per `06§6`. Underpins `block_on` / `wake_up` for the
// scheduler (`13§10`), pipe / eventfd / signalfd / timerfd / futex
// blocking semantics (`24§3`-`§8`), and the AF_UNIX state machine
// (`24§9`).
//
// Surface (this PR):
// - `add_waiter(Arc<Task>)` — register a sleeping task.
// - `remove_waiter(tid)` — pull a registered task back out (timeout
//   cancellation; pidfd close; signal interrupt).
// - `wake_one() -> Option<Arc<Task>>` — pop the FIFO head, transition
//   `Sleeping → Runnable`, return so the caller can hand off to the
//   scheduler's enqueue path.
// - `wake_all() -> Vec<Arc<Task>>` — drain.
//
// Lost-wakeup avoidance per `06§6`: the *condition-recheck under the
// queue's lock* is the wait-side caller's discipline — we hand them
// `with_lock_held(F)` so they can re-evaluate the condition before
// commit. The blocking call itself (`sched::block_on`) lands once HAL
// `Context` enables an actual context switch.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sched::{Task, TaskState};
use sync::{LockClass, SignalQueue, Spinlock};

/// Wait-queue body — visible to callers who need to perform the
/// `register + recheck condition + sleep` sequence atomically.
pub struct WaitQueueInner {
    queue: VecDeque<Arc<Task>>,
}

impl WaitQueueInner {
    /// # C: O(1)
    fn new() -> Self {
        Self { queue: VecDeque::new() }
    }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.queue.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.queue.is_empty() }

    /// Push `t` to the FIFO tail. Caller is expected to set
    /// `t.state = Sleeping` after the recheck succeeds and before
    /// dropping the lock; the queue does not mutate task state at
    /// register time.
    /// # C: O(1)
    pub fn push(&mut self, t: Arc<Task>) {
        self.queue.push_back(t);
    }

    /// Remove the registered task with `tid`, if any. Returns the
    /// `Arc<Task>` so the caller can decide whether to wake or drop
    /// (timeout vs cancel).
    /// # C: O(N)
    pub fn remove_by_tid(&mut self, tid: u32) -> Option<Arc<Task>> {
        let pos = self.queue.iter().position(|t| t.tid == tid)?;
        self.queue.remove(pos)
    }

    fn pop_front_runnable(&mut self) -> Option<Arc<Task>> {
        let t = self.queue.pop_front()?;
        // Transition Sleeping -> Runnable. The CAS may already see
        // `Runnable` if a concurrent `remove_by_tid` raced (e.g. from
        // a timeout); treat that as a no-op.
        let _ = t.cas_state(TaskState::Sleeping, TaskState::Runnable);
        Some(t)
    }
}

/// Wait queue per `06§6`. Generic over `LockClass` so consumers pick
/// the right rank for their subsystem (`SignalQueue` for per-task
/// pending signals; pipe / eventfd / futex use their own).
pub struct WaitQueue<C: LockClass = SignalQueue> {
    inner: Spinlock<WaitQueueInner, C>,
}

impl<C: LockClass> WaitQueue<C> {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(WaitQueueInner { queue: VecDeque::new() }) }
    }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.inner.lock().len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.inner.lock().is_empty() }

    /// Hand the caller the locked inner queue so they can re-check the
    /// wakeup condition AND register atomically (`06§6` lost-wakeup
    /// defense). Returns `f`'s result so the caller decides whether
    /// to commit (typically `state = Sleeping; sched()`) or bail.
    /// # C: O(1) plus `f`
    /// # Lk: this WaitQueue's lock acquired
    pub fn with_lock_held<R>(&self, f: impl FnOnce(&mut WaitQueueInner) -> R) -> R {
        let mut g = self.inner.lock();
        f(&mut *g)
    }

    /// Convenience: register the current task. Caller still owns the
    /// state-transition + reschedule discipline per `06§6`.
    /// # C: O(1)
    pub fn add_waiter(&self, t: Arc<Task>) {
        self.inner.lock().push(t);
    }

    /// Remove a waiter by `tid` (timeout / cancel paths). Returns the
    /// `Arc<Task>` if it was on the queue.
    /// # C: O(N)
    pub fn remove_waiter(&self, tid: u32) -> Option<Arc<Task>> {
        self.inner.lock().remove_by_tid(tid)
    }

    /// Wake the FIFO head; transitions `Sleeping → Runnable` via CAS
    /// and returns the task so the caller can hand it to the
    /// scheduler's enqueue path.
    /// # C: O(1)
    pub fn wake_one(&self) -> Option<Arc<Task>> {
        self.inner.lock().pop_front_runnable()
    }

    /// Drain the queue; transitions every task `Sleeping → Runnable`.
    /// # C: O(N)
    pub fn wake_all(&self) -> Vec<Arc<Task>> {
        let mut out = Vec::new();
        let mut g = self.inner.lock();
        while let Some(t) = g.pop_front_runnable() {
            out.push(t);
        }
        out
    }
}

impl<C: LockClass> Default for WaitQueue<C> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sched::{SchedClass, SchedPolicy, Task};
    use sync::SignalQueue;

    fn sleeping(tid: u32) -> Arc<Task> {
        let t = Arc::new(Task::new(tid, "w",
            SchedClass::Rt { prio: 1, policy: SchedPolicy::Fifo }));
        t.set_state(TaskState::Sleeping);
        t
    }

    type Wq = WaitQueue<SignalQueue>;

    #[test]
    fn new_is_empty() {
        let q = Wq::new();
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
    }

    #[test]
    fn wake_one_on_empty() {
        let q = Wq::new();
        assert!(q.wake_one().is_none());
    }

    #[test]
    fn add_then_wake_one_fifo() {
        let q = Wq::new();
        q.add_waiter(sleeping(1));
        q.add_waiter(sleeping(2));
        q.add_waiter(sleeping(3));
        assert_eq!(q.len(), 3);

        let t = q.wake_one().unwrap();
        assert_eq!(t.tid, 1);
        assert_eq!(t.state(), TaskState::Runnable);
        let t = q.wake_one().unwrap();
        assert_eq!(t.tid, 2);
        let t = q.wake_one().unwrap();
        assert_eq!(t.tid, 3);
        assert!(q.wake_one().is_none());
        assert!(q.is_empty());
    }

    #[test]
    fn wake_all_drains_and_runnable() {
        let q = Wq::new();
        for i in 0..5 { q.add_waiter(sleeping(i)); }
        let woken = q.wake_all();
        assert_eq!(woken.len(), 5);
        for (i, t) in woken.iter().enumerate() {
            assert_eq!(t.tid, i as u32);
            assert_eq!(t.state(), TaskState::Runnable);
        }
        assert!(q.is_empty());
    }

    #[test]
    fn remove_by_tid_finds_and_pulls() {
        let q = Wq::new();
        q.add_waiter(sleeping(10));
        q.add_waiter(sleeping(20));
        q.add_waiter(sleeping(30));
        let t = q.remove_waiter(20).unwrap();
        assert_eq!(t.tid, 20);
        // State unchanged — caller (timeout / cancel) decides.
        assert_eq!(t.state(), TaskState::Sleeping);
        assert_eq!(q.len(), 2);
        // Head is still 10.
        let t = q.wake_one().unwrap();
        assert_eq!(t.tid, 10);
        let t = q.wake_one().unwrap();
        assert_eq!(t.tid, 30);
    }

    #[test]
    fn remove_missing_returns_none() {
        let q = Wq::new();
        q.add_waiter(sleeping(1));
        assert!(q.remove_waiter(99).is_none());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn with_lock_held_supports_recheck_pattern() {
        // Mimic the `06§6` lost-wakeup pattern: caller holds the lock
        // across a recheck-then-register decision.
        let q = Wq::new();
        let t = sleeping(7);
        let condition_met = false;

        let registered = q.with_lock_held(|inner| {
            if condition_met {
                false
            } else {
                inner.push(Arc::clone(&t));
                true
            }
        });
        assert!(registered);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn wake_one_on_already_runnable_is_noop_for_state() {
        // If a concurrent path already CAS'd the task to Runnable
        // (e.g. timeout race), wake_one still pops and returns it,
        // but `cas_state(Sleeping, Runnable)` silently fails — state
        // remains Runnable.
        let q = Wq::new();
        let t = sleeping(1);
        t.set_state(TaskState::Runnable);
        q.add_waiter(t);
        let t = q.wake_one().unwrap();
        assert_eq!(t.state(), TaskState::Runnable);
    }
}
