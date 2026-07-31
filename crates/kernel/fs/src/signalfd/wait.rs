//! Blocking-read parking for signalfd, isolated behind four calls so the
//! dequeue loop in `file.rs` carries no target-gated bodies.
//!
//! A blocked signalfd reader is woken directly by signal delivery
//! (`signal_wake_up`); this list supplies the race-free Sleeping publication
//! and owns the temporary task reference while the reader is parked — the
//! same shape `rt_sigtimedwait` uses, since the two consume the same queues.

#![cfg(target_os = "oxide-kernel")]

static SIGNALFD_READERS: sched::live::WaitList = sched::live::WaitList::new();

/// Publish Sleeping on the reader list before the post-park recheck. # C: O(1)
pub(super) fn park() {
    // SAFETY: process context; the caller either yields immediately or
    // cancels the park after its own recheck observes an arrival.
    unsafe { SIGNALFD_READERS.park_with_deadline(0); }
}

/// Undo a park whose recheck found work. # C: O(1)
pub(super) fn cancel() { SIGNALFD_READERS.cancel_current_park(); }

/// Drop off the list on a non-parking exit. # C: O(1)
pub(super) fn leave() { SIGNALFD_READERS.remove_current(); }

/// Hand the CPU over while Sleeping on the list. # C: O(1)
pub(super) fn yield_now() {
    // SAFETY: the task is Sleeping on the published wait list; signal delivery
    // transitions it back to Runnable.
    unsafe { sched::live::park_yield(); }
}
