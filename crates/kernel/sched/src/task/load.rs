//! Task-owned load contribution across block/wake handoff.

use core::sync::atomic::Ordering;

use super::{Task, TaskState, WaitState};

const LOAD_CONTRIBUTING_BIT: u8 = 0x40;

impl Task {
    /// Claim a sleeping task for wake placement while retaining whether its
    /// completed block contributes to load. # C: O(1)
    pub fn claim_wake(&self) -> bool {
        self.debug_check_canary("claim_wake");
        let mut seen = self.state.load(Ordering::Acquire);
        loop {
            if TaskState::from_u8(seen) != Some(TaskState::Sleeping) { return false; }
            let next = (seen & !TaskState::LIFECYCLE_MASK) | TaskState::Waking as u8;
            match self.state.compare_exchange_weak(seen, next, Ordering::AcqRel,
                                                   Ordering::Acquire) {
                Ok(_) => return true,
                Err(now) => seen = now,
            }
        }
    }

    /// Mark a completed uninterruptible block exactly once. Freezer sleep is
    /// excluded from system load. # C: O(1)
    pub(crate) fn mark_load_blocked(&self) -> bool {
        let mut seen = self.state.load(Ordering::Acquire);
        loop {
            if TaskState::from_u8(seen) != Some(TaskState::Sleeping)
                || WaitState::from_state_bits(seen) == WaitState::Interruptible
                || self.frozen.load(Ordering::Acquire)
                || seen & LOAD_CONTRIBUTING_BIT != 0
            {
                return false;
            }
            match self.state.compare_exchange_weak(seen, seen | LOAD_CONTRIBUTING_BIT,
                                                   Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(now) => seen = now,
            }
        }
    }

    /// Consume the blocked-load ownership when wake activation begins.
    /// # C: O(1)
    pub(crate) fn take_load_blocked(&self) -> bool {
        self.state.fetch_and(!LOAD_CONTRIBUTING_BIT, Ordering::AcqRel)
            & LOAD_CONTRIBUTING_BIT != 0
    }
}
