//! A bounded partition view over one canonical whole-disk backend.

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::{BlockCompletion, BlockDevice, BlockError, BlockRequest, KResult, QueueLimits};

/// Block-device view constrained to one discovered partition extent.
pub struct PartitionDevice {
    parent: Arc<dyn BlockDevice>,
    start_block: u64,
    capacity_blocks: u64,
}

impl PartitionDevice {
    /// Construct a view whose range is wholly within `parent`. # C: O(1)
    pub fn new(parent: Arc<dyn BlockDevice>, start_block: u64, capacity_blocks: u64) -> Option<Arc<Self>> {
        let end = start_block.checked_add(capacity_blocks)?;
        (capacity_blocks != 0 && end <= parent.capacity_blocks()).then(|| Arc::new(Self { parent, start_block, capacity_blocks }))
    }

    fn rebase(&self, request: &mut BlockRequest) -> KResult<()> {
        let end = request.start_block.checked_add(u64::from(request.len_blocks)).ok_or(BlockError::Einval)?;
        if end > self.capacity_blocks { return Err(BlockError::Eio); }
        request.start_block = request.start_block.checked_add(self.start_block).ok_or(BlockError::Einval)?;
        Ok(())
    }
}

impl BlockDevice for PartitionDevice {
    fn block_size(&self) -> u32 { self.parent.block_size() }
    fn queue_limits(&self) -> KResult<QueueLimits> { self.parent.queue_limits() }
    fn supports_discard(&self) -> bool { self.parent.supports_discard() }
    fn capacity_blocks(&self) -> u64 { self.capacity_blocks }
    fn submit(&self, mut request: BlockRequest, completion: BlockCompletion) {
        let start = self.start_block;
        if let Err(error) = self.rebase(&mut request) { completion(request, Err(error)); return; }
        self.parent.submit(request, Box::new(move |mut completed, result| {
            completed.start_block -= start;
            completion(completed, result);
        }));
    }
    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        self.rebase(request)?;
        let result = self.parent.submit_sync(request);
        request.start_block -= self.start_block;
        result
    }
    fn flush(&self) -> KResult<()> { self.parent.flush() }
    fn can_poll(&self) -> bool { self.parent.can_poll() }
    fn poll_completions(&self) -> usize { self.parent.poll_completions() }
    fn swap_slot_free_notify(&self, start_block: u64, len_blocks: u32) -> KResult<()> {
        let end = start_block.checked_add(u64::from(len_blocks)).ok_or(BlockError::Einval)?;
        if end > self.capacity_blocks { return Err(BlockError::Eio); }
        self.parent.swap_slot_free_notify(start_block + self.start_block, len_blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockOp, MemDisk};
    use alloc::vec;
    use sync::TaskList;

    #[test]
    fn partition_io_is_rebased_and_cannot_escape_its_extent() {
        let parent: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 16);
        let view = PartitionDevice::new(Arc::clone(&parent), 4, 4).expect("in-bounds view");
        let mut write = BlockRequest::new_write(1, 1, vec![0x5a; 512]);
        view.submit_sync(&mut write).expect("partition write");
        let mut parent_read = BlockRequest::new_read(5, 1, 512);
        parent.submit_sync(&mut parent_read).expect("parent read");
        assert_eq!(parent_read.buffer, vec![0x5a; 512]);
        let mut overrun = BlockRequest { op: BlockOp::Read, start_block: 4, len_blocks: 1, buffer: vec![0; 512], ..Default::default() };
        assert_eq!(view.submit_sync(&mut overrun), Err(BlockError::Eio));
        assert_eq!(overrun.start_block, 4, "failed requests remain in partition coordinates");
    }
}
