//! NVMe namespace geometry and removal predicates.

use super::*;

impl NvmeBlk {
    pub(super) fn chunk_bytes(&self) -> usize { Nvme::MAX_XFER as usize }

    pub(super) fn unavailable(&self) -> bool {
        self.removed.load(Ordering::Acquire) || self.poisoned.load(Ordering::Acquire)
    }
}
