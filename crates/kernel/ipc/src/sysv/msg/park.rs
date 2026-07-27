//! Park sequencing for the blocking halves of `msgsnd` / `msgrcv`.
//!
//! Linux publishes the sleeper into `q_senders` / `q_receivers` while holding
//! `ipc_lock_object`, drops the lock, and only then calls `schedule()`. The
//! shared [`crate::sysv::block::park_until`] fuses registration and yield into
//! one call, which cannot express that ordering: a publisher that took the
//! queue lock between the no-progress decision and the registration would have
//! woken an empty list. Splitting the two halves keeps the registration inside
//! the same critical section as the condition test.

use crate::sysv::block::{self, Wake, WaitList};

/// `msgsnd` / `msgrcv` block without a timeout; the deadline scanner is unused.
#[cfg(target_os = "oxide-kernel")]
const NO_DEADLINE: u64 = 0;

/// Publish the running task onto `wl` while the caller still holds the queue
/// lock. Caller MUST drop that lock and call [`yield_and_classify`] next.
///
/// # SAFETY: caller is the running task on this CPU in process context with
/// the runqueue installed and preemption disabled, and yields immediately
/// after dropping the queue lock.
/// # C: O(N_waiters)
/// # Ctx: process
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn arm(wl: &WaitList) {
    // SAFETY: `arm`'s documented contract is exactly `park_interruptible_with_deadline`'s — running task on this CPU, preempt-off, runqueue installed, and the caller yields immediately after dropping the queue lock.
    unsafe { wl.park_interruptible_with_deadline(NO_DEADLINE); }
}

/// Yield after the queue lock is dropped, then classify the wake. A pending
/// signal unwinds the caller with `EINTR` (Linux returns `-ERESTARTNOHAND`;
/// this kernel surfaces `EINTR` directly, matching the futex wait path in
/// `live::futex::wait`).
///
/// # SAFETY: caller armed a park with [`arm`] and has dropped every lock a
/// waker needs; process context with the runqueue installed.
/// # C: O(1) plus the sleep
/// # Ctx: process
/// # Sleeps: yes
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn yield_and_classify() -> Wake {
    // SAFETY: process context with the runqueue installed and preemption disabled, as `schedule` requires; this call is the yield the `arm` above published for.
    unsafe { sched::live::schedule(); }
    if block::signal_pending() { Wake::Signal } else { Wake::Retry }
}

/// # SAFETY: hosted stub; no scheduler exists, so nothing is published.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn arm(_wl: &WaitList) {}

/// # SAFETY: hosted stub; reports [`Wake::Signal`] so the callers' retry loops
/// terminate with `EINTR` instead of spinning.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn yield_and_classify() -> Wake { let _ = block::signal_pending(); Wake::Signal }
