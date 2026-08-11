//! CLONE_VFORK completion wait. The child arms `vfork_pending` before it is
//! runnable; exec or exit clears it before waking this shared completion queue.

use core::sync::atomic::Ordering;

use crate::{Task, WaitOutcome};

use super::{WaitList, wait_event_killable};

static WAIT: WaitList = WaitList::new();

/// Wait for one vfork child to release its parent's borrowed address space.
/// Returns false when a fatal signal interrupted the killable completion wait.
/// # SAFETY: process context on the child's parent, no lock held by vfork_done.
/// # C: O(N_wakeups)
pub unsafe fn wait_for_done(child: &Task) -> bool {
    // SAFETY: forwards this function's process-context contract to the shared
    // completion predicate loop; child stays referenced by the caller.
    matches!(unsafe { wait_event_killable(&WAIT,
        || !child.vfork_pending.load(Ordering::Acquire)) }, WaitOutcome::Ready)
}

/// Release all parents whose child may have completed. # C: O(N_vfork_waiters)
pub fn wake() { WAIT.wake_all(); }
