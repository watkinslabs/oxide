//! USB Bulk-Only SCSI disk adapter for the canonical block registry.

extern crate alloc;

use alloc::sync::Arc;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult, QueueLimits};

use crate::probe::{storage_command, UsbDevice};

const SCSI_DISK_DRIVER: block::registry::BlockDriver = block::registry::BlockDriver::fixed("sd", block::uapi::SCSI_DISK_MAJOR);
const STORAGE_DMA_BYTES: usize = 4096;
const MAX_RW10_BLOCKS: u32 = u16::MAX as u32;

struct UsbStorageBlock {
    device: Arc<UsbDevice>,
    capacity: u64,
    block_bytes: u32,
}

impl UsbStorageBlock {
    fn transfer(&self, request: &mut BlockRequest, write: bool) -> KResult<()> {
        if request.len_blocks == 0 || request.len_blocks > MAX_RW10_BLOCKS
            || request.start_block > u64::from(u32::MAX)
            || request.start_block.checked_add(u64::from(request.len_blocks)).is_none_or(|end| end > self.capacity) {
            return Err(BlockError::Einval);
        }
        let bytes = (request.len_blocks as usize).checked_mul(self.block_bytes as usize).ok_or(BlockError::Einval)?;
        if bytes > STORAGE_DMA_BYTES || request.buffer.len() != bytes { return Err(BlockError::Einval); }
        let blocks = request.len_blocks as u16;
        let lba = request.start_block as u32;
        if write {
            let cdb = crate::storage::write10_cdb(lba, blocks).ok_or(BlockError::Einval)?;
            storage_command(&self.device, 3, &cdb, bytes as u32, false, Some(&request.buffer)).ok_or(BlockError::Eio)?;
        } else {
            let cdb = crate::storage::read10_cdb(lba, blocks).ok_or(BlockError::Einval)?;
            let data = storage_command(&self.device, 3, &cdb, bytes as u32, true, None).ok_or(BlockError::Eio)?;
            if data.len() != bytes { return Err(BlockError::Eio); }
            request.buffer = data;
        }
        Ok(())
    }
}

impl BlockDevice for UsbStorageBlock {
    fn block_size(&self) -> u32 { self.block_bytes }
    fn queue_limits(&self) -> KResult<QueueLimits> { QueueLimits::for_logical_block_size(self.block_bytes) }
    fn capacity_blocks(&self) -> u64 { self.capacity }

    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        match request.op {
            BlockOp::Read => self.transfer(request, false),
            BlockOp::Write => self.transfer(request, true),
            BlockOp::Flush => self.flush(),
            BlockOp::Discard | BlockOp::WriteZeroes { .. } => Err(BlockError::Eopnotsupp),
        }
    }

    fn flush(&self) -> KResult<()> {
        let cdb = [0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        storage_command(&self.device, 4, &cdb, 0, false, Some(&[])).map(|_| ()).ok_or(BlockError::Eio)
    }
}

/// Publish a discovered transparent-SCSI USB disk through the sole block registry.
/// # C: O(registry publication)
pub(crate) fn register(device: Arc<UsbDevice>, capacity: u64, block_bytes: u32) -> Option<block::ScsiDiskName> {
    if capacity == 0 || !block_bytes.is_power_of_two() || block_bytes < 512 || block_bytes as usize > STORAGE_DMA_BYTES { return None; }
    let name = block::reserve_scsi_disk_name()?;
    let disk = Arc::new(UsbStorageBlock { device, capacity, block_bytes });
    let index = block::registry::register_with_driver(SCSI_DISK_DRIVER, name.as_str(), None, disk);
    (index != 0).then_some(name)
}
