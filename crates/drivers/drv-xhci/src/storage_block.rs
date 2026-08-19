//! USB Bulk-Only SCSI transport for the shared SCSI disk mid-layer.

extern crate alloc;

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use block::{BlockError, KResult, QueueLimits};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::probe::{control_complete, storage_command, UsbDevice};

struct UsbStorageTransport {
    device: Arc<UsbDevice>,
    serial: Option<String>,
    max_lun: scsi::Lun,
    next_tag: AtomicU32,
}

impl UsbStorageTransport {
    fn new(device: Arc<UsbDevice>) -> Option<Arc<Self>> {
        let (max_lun, serial) = {
            let _transaction = device.lock_transfer();
            let (irq, slot, done, serial) = device.with_transport(|mmio, irq, _, state| {
                state.device.storage_interface()?;
                let slot = state.slot;
                let done = state.device.submit_storage_max_lun(mmio, slot)?;
                Some((irq, slot, done, state.device.usb_serial().map(String::from)))
            })??;
            let max_lun = if control_complete(irq, done, slot) {
                device.with_transport(|_, _, _, state| state.device.storage_max_lun())?.unwrap_or(0)
            } else {
                // USB Bulk-Only permits a STALL here; scan the required LUN 0.
                0
            };
            (max_lun, serial)
        };
        let max_lun = scsi::Lun::new(u64::from(max_lun));
        Some(Arc::new(Self { device, serial, max_lun, next_tag: AtomicU32::new(1) }))
    }

    fn next_tag(&self) -> u32 { self.next_tag.fetch_add(1, Ordering::Relaxed) }

    fn request_sense(&self, lun: scsi::Lun, timeout_ms: u32) -> KResult<Vec<u8>> {
        let result = storage_command(&self.device, self.next_tag(), lun, &[0x03, 0, 0, 0, scsi::SENSE_BYTES as u8, 0],
            scsi::SENSE_BYTES as u32, true, None, timeout_ms).ok_or(BlockError::Eio)?;
        if result.status != crate::storage::CswStatus::Passed || result.residue != 0 { return Err(BlockError::Eio); }
        Ok(result.data)
    }

    fn execute_with_timeout_inner(&self, lun: scsi::Lun, command: &scsi::Command, data: &mut [u8],
                                  direction: scsi::DataDirection, timeout_ms: u32) -> KResult<scsi::CommandCompletion> {
        if lun > self.max_lun { return Err(BlockError::Enxio); }
        if data.len() > crate::device::STORAGE_MAX_TRANSFER_BYTES { return Err(BlockError::Einval); }
        let device_to_host = matches!(direction, scsi::DataDirection::FromDevice);
        let out = match direction {
            scsi::DataDirection::FromDevice => None,
            scsi::DataDirection::ToDevice | scsi::DataDirection::None => Some(&data[..]),
        };
        let result = storage_command(&self.device, self.next_tag(), lun, command.bytes(), data.len() as u32,
            device_to_host, out, timeout_ms);
        let Some(result) = result else { return Err(BlockError::Eio); };
        let transferred = data.len().checked_sub(result.residue as usize).ok_or(BlockError::Eio)?;
        if device_to_host {
            if result.data.len() != data.len() { return Err(BlockError::Eio); }
            data[..transferred].copy_from_slice(&result.data[..transferred]);
        }
        match result.status {
            crate::storage::CswStatus::Passed => Ok(scsi::CommandCompletion::good_with_resid(result.residue)),
            crate::storage::CswStatus::Failed => {
                let sense = if command.opcode() == 0x03 { Vec::new() }
                    else { self.request_sense(lun, timeout_ms).unwrap_or_else(|_| Vec::new()) };
                Ok(scsi::CommandCompletion::check_condition(result.residue, &sense))
            }
            crate::storage::CswStatus::PhaseError => Err(BlockError::Eio),
        }
    }
}

impl scsi::Transport for UsbStorageTransport {
    fn max_lun(&self) -> scsi::Lun { self.max_lun }

    fn execute(&self, lun: scsi::Lun, command: &scsi::Command, data: &mut [u8],
               direction: scsi::DataDirection) -> KResult<scsi::CommandCompletion> {
        self.execute_with_timeout_inner(lun, command, data, direction, 1_000)
    }

    fn execute_with_timeout(&self, lun: scsi::Lun, command: &scsi::Command, data: &mut [u8],
                            direction: scsi::DataDirection, timeout_ms: u32) -> KResult<scsi::CommandCompletion> {
        self.execute_with_timeout_inner(lun, command, data, direction, timeout_ms)
    }

    fn retry_delay(&self, delay_ms: u32) -> KResult<()> {
        if delay_ms == 0 { return Ok(()); }
        let wait = sched::live::WaitList::new();
        let deadline = sched::deadline::clock::now_ns().saturating_add(u64::from(delay_ms).saturating_mul(1_000_000));
        // SAFETY: a storage command has completed and released the controller
        // transaction lock before this retry delay; this is process context.
        let _ = unsafe { sched::live::wait_event_uninterruptible_until(&wait, deadline,
            sched::deadline::clock::now_ns, || false) };
        Ok(())
    }

    fn sg_io_max_transfer_bytes(&self) -> Option<usize> { Some(crate::device::STORAGE_MAX_TRANSFER_BYTES) }

    fn queue_limits(&self, block_size: u32) -> KResult<QueueLimits> {
        if block_size as usize > crate::device::STORAGE_MAX_TRANSFER_BYTES { return Err(BlockError::Einval); }
        Ok(QueueLimits::for_logical_block_size(block_size)?.with_features(block::QueueFeatures::WRITE_CACHE))
    }
}

/// Scan every reported transparent-SCSI USB LUN through the shared host owner.
/// # C: O(LUNs × inquiry/capacity)
pub(crate) fn register(device: Arc<UsbDevice>) -> Vec<block::ScsiDiskName> {
    let Some(transport) = UsbStorageTransport::new(device) else { return Vec::new(); };
    scsi::scan_and_publish(transport.clone(), transport.serial.as_deref())
}
