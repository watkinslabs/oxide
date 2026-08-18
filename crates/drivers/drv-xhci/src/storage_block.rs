//! USB Bulk-Only SCSI transport for the shared SCSI disk mid-layer.

extern crate alloc;

use alloc::sync::Arc;
use block::{BlockError, KResult, QueueLimits};

use crate::probe::{storage_command, UsbDevice};

struct UsbStorageTransport {
    device: Arc<UsbDevice>,
}

impl scsi::Transport for UsbStorageTransport {
    fn execute(&self, command: &scsi::Command, data: &mut [u8], direction: scsi::DataDirection) -> KResult<()> {
        if data.len() > crate::device::STORAGE_MAX_TRANSFER_BYTES { return Err(BlockError::Einval); }
        let cdb = command.bytes();
        match direction {
            scsi::DataDirection::FromDevice => {
                let response = storage_command(&self.device, 3, cdb, data.len() as u32, true, None).ok_or(BlockError::Eio)?;
                if response.len() != data.len() { return Err(BlockError::Eio); }
                data.copy_from_slice(&response);
                Ok(())
            }
            scsi::DataDirection::ToDevice => {
                storage_command(&self.device, 3, cdb, data.len() as u32, false, Some(data)).map(|_| ()).ok_or(BlockError::Eio)
            }
            scsi::DataDirection::None => {
                storage_command(&self.device, 4, cdb, 0, false, Some(&[])).map(|_| ()).ok_or(BlockError::Eio)
            }
        }
    }

    fn queue_limits(&self, block_size: u32) -> KResult<QueueLimits> {
        Ok(QueueLimits::for_logical_block_size(block_size)?.with_features(block::QueueFeatures::WRITE_CACHE))
    }
}

/// Publish a discovered transparent-SCSI USB disk through the sole block registry.
/// # C: O(registry publication)
pub(crate) fn register(device: Arc<UsbDevice>, capacity: u64, block_bytes: u32) -> Option<block::ScsiDiskName> {
    if capacity == 0 || !block_bytes.is_power_of_two() || block_bytes < 512 || block_bytes as usize > crate::device::STORAGE_MAX_TRANSFER_BYTES { return None; }
    scsi::publish(Arc::new(UsbStorageTransport { device }), block_bytes, capacity, None)
}
