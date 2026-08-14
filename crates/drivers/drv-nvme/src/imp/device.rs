//! NVMe namespace geometry and removal predicates.

use super::*;

impl NvmeBlk {
    pub(super) fn chunk_bytes(&self) -> usize { Nvme::MAX_XFER as usize }

    pub(super) fn unavailable(&self) -> bool {
        self.removed.load(Ordering::Acquire) || self.poisoned.load(Ordering::Acquire)
    }

    /// Stop an unrecoverable controller once, fail every request still owned
    /// by its queue, then release the IRQ endpoint and DMA-visible frames.
    /// # C: O(controller shutdown + owned request completions)
    pub(super) fn recover_terminal_failure(&self) {
        self.poisoned.store(true, Ordering::Release);
        self.quiesce_and_free();
    }
}
