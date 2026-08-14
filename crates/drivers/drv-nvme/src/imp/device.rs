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

    /// Coalesce periodic timeout observations into one process-context worker.
    /// # C: O(1)
    pub(super) fn claim_timeout_worker(&self) -> bool {
        self.timeout_worker_queued.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Let a later periodic observation queue the next timeout stage.
    /// # C: O(1)
    pub(super) fn release_timeout_worker(&self) {
        self.timeout_worker_queued.store(false, Ordering::Release);
    }

    /// Stop a controller with corrupt completion ownership. This is not a
    /// reset path: it releases the terminal controller resources once.
    /// # C: O(controller shutdown + owned request completions)
    pub(super) fn recover_terminal_failure(&self) {
        self.poisoned.store(true, Ordering::Release);
        self.quiesce_and_free();
    }
}
