//! Common `sd` block-device translation above one discovered LUN.

extern crate alloc;

use alloc::sync::Arc;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult, QueueLimits};

use crate::{Command, DataDirection, Lun, Transport, READ_10, READ_16, SYNCHRONIZE_CACHE_10, WRITE_10, WRITE_16};

/// The `sd`-style block device above one addressed SCSI transport. # C: O(1)
pub struct Disk { transport: Arc<dyn Transport>, lun: Lun, block_size: u32, capacity: u64 }

impl Disk {
    /// Build one disk after discovery has established its capacity and sector
    /// size. # C: O(1)
    pub fn new(transport: Arc<dyn Transport>, lun: Lun, block_size: u32, capacity: u64) -> KResult<Arc<Self>> {
        if capacity == 0 || !block_size.is_power_of_two() || block_size < 512 { return Err(BlockError::Einval); }
        Ok(Arc::new(Self { transport, lun, block_size, capacity }))
    }

    /// Addressed LUN this block device serves. # C: O(1)
    pub const fn lun(&self) -> Lun { self.lun }

    fn cdb(&self, write: bool, lba: u64, blocks: u32) -> KResult<Command> {
        let end = lba.checked_add(u64::from(blocks)).ok_or(BlockError::Einval)?;
        if end > self.capacity { return Err(BlockError::Eio); }
        if lba <= u64::from(u32::MAX) && blocks <= u32::from(u16::MAX) {
            let mut cdb = [0u8; 10];
            cdb[0] = if write { WRITE_10 } else { READ_10 };
            cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
            cdb[7..9].copy_from_slice(&(blocks as u16).to_be_bytes());
            Command::new(&cdb)
        } else {
            let mut cdb = [0u8; 16];
            cdb[0] = if write { WRITE_16 } else { READ_16 };
            cdb[2..10].copy_from_slice(&lba.to_be_bytes());
            cdb[10..14].copy_from_slice(&blocks.to_be_bytes());
            Command::new(&cdb)
        }
    }

    fn transfer(&self, request: &mut BlockRequest, write: bool) -> KResult<()> {
        let bytes = (request.len_blocks as usize).checked_mul(self.block_size as usize).ok_or(BlockError::Einval)?;
        if request.buffer.len() != bytes { return Err(BlockError::Einval); }
        if request.len_blocks == 0 { return Ok(()); }
        let command = self.cdb(write, request.start_block, request.len_blocks)?;
        self.transport.execute(self.lun, &command, &mut request.buffer,
            if write { DataDirection::ToDevice } else { DataDirection::FromDevice })
    }
}

impl BlockDevice for Disk {
    fn block_size(&self) -> u32 { self.block_size }
    fn queue_limits(&self) -> KResult<QueueLimits> { self.transport.queue_limits(self.block_size) }
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
        self.transport.execute(self.lun, &Command::new(&[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0])?,
            &mut [], DataDirection::None)
    }
}

/// Publish a SCSI disk through the shared `sd*` namespace at LUN zero.
/// # C: O(registry publication)
pub fn publish(transport: Arc<dyn Transport>, block_size: u32, capacity: u64, serial: Option<&str>) -> Option<block::ScsiDiskName> {
    publish_lun(transport, Lun::ZERO, block_size, capacity, serial)
}

/// Publish one addressed direct-access SCSI LUN through the shared `sd*`
/// namespace. # C: O(registry publication)
pub fn publish_lun(transport: Arc<dyn Transport>, lun: Lun, block_size: u32, capacity: u64,
                   serial: Option<&str>) -> Option<block::ScsiDiskName> {
    let disk = Disk::new(transport, lun, block_size, capacity).ok()?;
    let name = block::reserve_scsi_disk_name()?;
    let index = block::registry::register_with_driver(
        block::registry::BlockDriver::fixed("sd", block::uapi::SCSI_DISK_MAJOR), name.as_str(), serial, disk);
    (index != 0).then_some(name)
}

/// Publish an existing physical endpoint through the SCSI mid-layer. # C: O(registry publication)
pub fn publish_block_transport(inner: Arc<dyn BlockDevice>, serial: Option<&str>) -> Option<block::ScsiDiskName> {
    let block_size = inner.block_size();
    let capacity = inner.capacity_blocks();
    publish(crate::BlockTransport::new(inner), block_size, capacity, serial)
}

/// SCSI has no global queue to start; host transports scan and publish their
/// own discovered LUNs. # C: O(1)
pub fn init() {}
