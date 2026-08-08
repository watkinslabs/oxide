//! `CoherentDev` — the decorator that keeps a filesystem mounted on a disk and
//! a raw open of the same disk from disagreeing about a block.
//!
//! COHERENCY RULE (narrower than the reference's, and stated because it is a
//! choice): every I/O that reaches a registered disk through its published
//! device handle is made coherent with that disk's page cache at submission
//! time — before an external WRITE the overlapping cached pages are written
//! back and then dropped, and before an external READ the overlapping dirty
//! pages are written back. A filesystem's metadata and data therefore both
//! agree with a raw `/dev/<disk>` open in both directions, which is stronger
//! than the reference gives for file data and weaker in exactly one place: I/O
//! a driver performs internally, below its registered handle, is invisible
//! here and stays outside the rule.
//!
//! The decorator sits ABOVE the accounting decorator and the mapping submits
//! BELOW it, so writeback is counted like every other request and cannot
//! recursively invalidate the pages it is writing.

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};

use crate::blockdev::{BlockCompletion, BlockDevice, BlockRequest};
use crate::queue_limits::QueueLimits;
use crate::types::{BlockOp, KResult, PAGE_BYTES};

use super::mapping::BdevMapping;

/// Half-open page-index span `[first, last_excl)` covering the byte range
/// `[start, end)`. `end == u64::MAX` means "to the end of the object", which
/// spans to `u64::MAX` rather than wrapping. # C: O(1)
pub fn page_span(start: u64, end: u64) -> (u64, u64) {
    let pg = PAGE_BYTES as u64;
    let lo = start / pg;
    let hi = if end == u64::MAX { u64::MAX } else { (end + pg - 1) / pg };
    (lo, core::cmp::max(lo, hi))
}

/// Byte range one request addresses, `None` for an operation that transfers
/// nothing (a barrier). # C: O(1)
fn request_range(req: &BlockRequest, block_size: u32) -> Option<(u64, u64)> {
    if req.op == BlockOp::Flush || req.len_blocks == 0 { return None; }
    let bs = block_size as u64;
    let start = req.start_block.saturating_mul(bs);
    Some((start, start.saturating_add((req.len_blocks as u64).saturating_mul(bs))))
}

/// Coherence decorator over one registered disk.
pub struct CoherentDev {
    inner: Arc<dyn BlockDevice>,
    /// Weak because the disk owns both this decorator and the mapping, and the
    /// mapping owns the device handle underneath this one.
    mapping: Weak<BdevMapping>,
}

impl CoherentDev {
    /// Wrap `inner` so external I/O reconciles with `mapping` first. # C: O(1)
    pub fn wrap(inner: Arc<dyn BlockDevice>, mapping: Weak<BdevMapping>) -> Arc<dyn BlockDevice> {
        Arc::new(Self { inner, mapping })
    }

    /// Reconcile the cache with an external request about to be submitted.
    /// # C: O(pages in range), O(1) when the disk has never been opened raw
    fn reconcile(&self, req: &BlockRequest) {
        let Some(mapping) = self.mapping.upgrade() else { return; };
        if mapping.nrpages() == 0 { return; }
        let Some((start, end)) = request_range(req, self.inner.block_size()) else { return; };
        match req.op {
            BlockOp::Read => mapping.flush_range(start, end),
            _ => mapping.flush_and_invalidate_range(start, end),
        }
    }
}

impl BlockDevice for CoherentDev {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn queue_limits(&self) -> KResult<QueueLimits> { self.inner.queue_limits() }
    fn supports_discard(&self) -> bool { self.inner.supports_discard() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }

    fn submit(&self, request: BlockRequest, completion: BlockCompletion) {
        self.reconcile(&request);
        self.inner.submit(request, Box::new(completion));
    }

    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        self.reconcile(request);
        self.inner.submit_sync(request)
    }

    fn flush(&self) -> KResult<()> { self.inner.flush() }

    fn swap_slot_free_notify(&self, start_block: u64, len_blocks: u32) -> KResult<()> {
        self.inner.swap_slot_free_notify(start_block, len_blocks)
    }
}
