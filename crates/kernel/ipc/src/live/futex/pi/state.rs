use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sched::{SchedClass, Task};
use sync::{Spinlock, Tty as TtyClass};

use super::super::core::Key;

/// A parked `FUTEX_LOCK_PI` waiter's grant slot. Written under [`PI_TABLE`],
/// read by the waiter after it drops the lock and parks, so the waiter can
/// tell an ownership handoff from a timeout or a signal without re-taking the
/// table lock in a context where it may already be gone.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum Grant {
    /// Still queued, not yet the owner.
    Pending = 0,
    /// This waiter is now the owner; the user word already names its TID.
    Owner = 1,
    /// Same as [`Grant::Owner`], plus the previous owner died holding the
    /// mutex, so the word carries `FUTEX_OWNER_DIED`.
    OwnerDied = 2,
}

pub(crate) struct PiWaiter {
    pub(crate) task: Arc<Task>,
    pub(crate) tid: u32,
    /// A [`Grant`] discriminant. `Arc` so the waiter keeps its own handle after
    /// the entry has been removed from the table by whoever granted it.
    pub(crate) grant: Arc<AtomicU32>,
    /// Set for a `FUTEX_WAIT_REQUEUE_PI` waiter still parked on the SOURCE
    /// futex: it may only be moved to `requeue_target` by a `FUTEX_CMP_REQUEUE_PI`,
    /// never woken by a plain `FUTEX_WAKE`.
    pub(crate) requeue_target: Option<Key>,
}

/// Kernel-side ownership record for one PI futex — Linux `futex_pi_state`.
///
/// It exists only while the futex is contended: created by the first waiter,
/// destroyed when the last waiter leaves. While it exists, `FUTEX_WAITERS`
/// stays set in the user word, so every lock and unlock is forced through the
/// kernel and the two views cannot drift apart.
pub(crate) struct PiState {
    pub(crate) key: Key,
    /// The user VA of the futex word. Kept alongside the key because a SHARED
    /// futex keys on the physical page, and the owner-death walk needs an
    /// address it can actually store through.
    pub(crate) uaddr: u64,
    /// `None` once the owner died without unlocking — the mutex is ownerless
    /// until the exit walk hands it to the top waiter.
    pub(crate) owner: Option<Arc<Task>>,
    pub(crate) owner_tid: u32,
    pub(crate) waiters: Vec<PiWaiter>,
}

impl PiState {
    /// Index of the waiter that must receive the mutex next: the highest
    /// scheduling class, ties broken by queue order (FIFO within a priority,
    /// matching what the rt runqueue does inside one priority bucket).
    /// # C: O(N_waiters)
    pub(crate) fn top_waiter(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        for (i, w) in self.waiters.iter().enumerate() {
            // A requeue-pi waiter is parked on a DIFFERENT futex; it is not a
            // candidate to own this one until it has actually been requeued.
            if w.requeue_target.is_some() { continue; }
            match best {
                None => best = Some(i),
                Some(b) if sched::pi_prio::outranks(
                    w.task.sched_class(), self.waiters[b].task.sched_class()) => best = Some(i),
                _ => {}
            }
        }
        best
    }

    /// Scheduling classes of every waiter, for the owner's boost computation.
    /// # C: O(N_waiters)
    pub(crate) fn waiter_classes(&self) -> Vec<SchedClass> {
        self.waiters.iter().map(|w| w.task.sched_class()).collect()
    }
}

/// Every live PI state, keyed the same way the wait queues are.
///
/// One flat table rather than a per-state lock: the operations that matter
/// (`lock`, `unlock`, the exit walk) all need to see the owner AND the waiter
/// set atomically, and nesting a per-state lock inside the table lock would
/// add a second lock order for no benefit at the contention levels a futex
/// table sees. Wakes and priority changes are performed AFTER the guard is
/// dropped, because both take runqueue locks.
pub(crate) static PI_TABLE: Spinlock<Vec<PiState>, TtyClass> = Spinlock::new(Vec::new());

/// Index of the state for `key`, if any.
/// # C: O(S)
pub(crate) fn find(tbl: &[PiState], key: Key) -> Option<usize> {
    tbl.iter().position(|s| s.key == key)
}

/// Re-derive the owner's PI boost from a state's current waiter set and apply
/// it. Must run with the table guard DROPPED — the requeue takes rq locks.
/// # C: O(N_waiters + N_cpus · log N)
pub(crate) fn reboost(owner: &Arc<Task>, classes: &[SchedClass]) {
    sched::live::pi_boost::apply_boost(owner, classes);
}

/// Grant `grant` to the waiter and wake it.
/// # C: O(1)
pub(crate) fn grant_and_wake(w: &PiWaiter, grant: Grant) {
    w.grant.store(grant as u32, Ordering::Release);
    // SAFETY: wake-site; the Arc in the waiter entry keeps the task alive
    // across the call, exactly as the non-PI `wake_key` path does.
    unsafe { sched::live::try_to_wake_up(w.task.clone()); }
}
