//! USB Bulk-Only SCSI transport for the shared SCSI disk mid-layer.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use block::{BlockError, KResult, QueueLimits};

use crate::probe::{control_complete, storage_command, UsbDevice};

struct UsbStorageTransport {
    device: Arc<UsbDevice>,
    max_lun: scsi::Lun,
}

impl UsbStorageTransport {
    fn new(device: Arc<UsbDevice>) -> Option<Arc<Self>> {
        let max_lun = device.with_transport(|mmio, irq, _, state| {
            state.device.storage_interface()?;
            let Some(done) = state.device.submit_storage_max_lun(mmio, state.slot) else { return Some(scsi::Lun::ZERO); };
            if !control_complete(irq, done, state.slot) { return Some(scsi::Lun::ZERO); }
            Some(scsi::Lun::new(u64::from(state.device.storage_max_lun().unwrap_or(0))))
        }).flatten()?;
        Some(Arc::new(Self { device, max_lun }))
    }
}

impl scsi::Transport for UsbStorageTransport {
    fn max_lun(&self) -> scsi::Lun { self.max_lun }

    fn execute(&self, lun: scsi::Lun, command: &scsi::Command, data: &mut [u8], direction: scsi::DataDirection) -> KResult<()> {
        if lun > self.max_lun { return Err(BlockError::Enxio); }
        if data.len() > crate::device::STORAGE_MAX_TRANSFER_BYTES { return Err(BlockError::Einval); }
        let cdb = command.bytes();
        match direction {
            scsi::DataDirection::FromDevice => {
                let response = storage_command(&self.device, 3, lun, cdb, data.len() as u32, true, None).ok_or(BlockError::Eio)?;
                if response.len() != data.len() { return Err(BlockError::Eio); }
                data.copy_from_slice(&response);
                Ok(())
            }
            scsi::DataDirection::ToDevice => {
                storage_command(&self.device, 3, lun, cdb, data.len() as u32, false, Some(data)).map(|_| ()).ok_or(BlockError::Eio)
            }
            scsi::DataDirection::None => {
                storage_command(&self.device, 4, lun, cdb, 0, false, Some(&[])).map(|_| ()).ok_or(BlockError::Eio)
            }
        }
    }

    fn queue_limits(&self, block_size: u32) -> KResult<QueueLimits> {
        if block_size as usize > crate::device::STORAGE_MAX_TRANSFER_BYTES { return Err(BlockError::Einval); }
        Ok(QueueLimits::for_logical_block_size(block_size)?.with_features(block::QueueFeatures::WRITE_CACHE))
    }
}

/// Scan every reported transparent-SCSI USB LUN through the shared host owner.
/// # C: O(LUNs × inquiry/capacity)
pub(crate) fn register(device: Arc<UsbDevice>) -> Vec<block::ScsiDiskName> {
    let Some(transport) = UsbStorageTransport::new(device) else { return Vec::new(); };
    scsi::scan_and_publish(transport, None)
}
