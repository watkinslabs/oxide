//! NVMe namespace geometry and removal predicates.

use super::*;

impl NvmeBlk {
    pub(super) fn chunk_bytes(&self) -> usize { Nvme::MAX_XFER as usize }

    pub(super) fn unavailable(&self) -> bool {
        self.removed.load(Ordering::Acquire) || self.poisoned.load(Ordering::Acquire) || self.resetting.load(Ordering::Acquire)
    }

    /// Mark a timeout unavailable until the process-context watchdog freezes
    /// and resets it after the submitting caller has dropped its gate token.
    /// # C: O(1)
    pub(super) fn mark_recovery_required(&self) { self.poisoned.store(true, Ordering::Release); }

    /// Stop a controller with corrupt completion ownership. This is not a
    /// reset path: it releases the terminal controller resources once.
    /// # C: O(controller shutdown + owned request completions)
    pub(super) fn recover_terminal_failure(&self) {
        self.poisoned.store(true, Ordering::Release);
        self.quiesce_and_free();
    }
}
