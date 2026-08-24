//! Common `sd` block-device translation above one discovered LUN.

extern crate alloc;

use alloc::sync::Arc;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult, QueueLimits};

use crate::{BlockDisposition, Command, CommandCompletion, DEFAULT_RETRIES, DataDirection, Lun, Transport, READ_10,
    READ_16, SYNCHRONIZE_CACHE_10, WRITE_10, WRITE_16, block_disposition};

/// The `sd`-style block device above one addressed SCSI transport. # C: O(1)
pub struct Disk { transport: Arc<dyn Transport>, lun: Lun, block_size: u32, capacity: u64, removable: bool }

impl Disk {
    /// Build one disk after discovery has established its capacity and sector
    /// size. # C: O(1)
    pub fn new(transport: Arc<dyn Transport>, lun: Lun, block_size: u32, capacity: u64) -> KResult<Arc<Self>> {
        Self::new_with_media(transport, lun, block_size, capacity, false)
    }

    /// Build one disk after discovery has established its capacity, sector
    /// size, and removable-medium state. # C: O(1)
    pub fn new_with_media(transport: Arc<dyn Transport>, lun: Lun, block_size: u32, capacity: u64,
                          removable: bool) -> KResult<Arc<Self>> {
        if capacity == 0 || !block_size.is_power_of_two() || block_size < 512 { return Err(BlockError::Einval); }
        Ok(Arc::new(Self { transport, lun, block_size, capacity, removable }))
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

    /// Execute ordinary block I/O through the common SCSI recovery decision.
    /// The host performs any nonzero delay in process context; SG_IO bypasses
    /// this helper so userspace receives its original completion untouched.
    /// # C: up to `DEFAULT_RETRIES + 1` commands
    fn execute_block(&self, command: &Command, data: &mut [u8], direction: DataDirection) -> KResult<()> {
        let mut retries = 0;
        loop {
            let completion = self.transport.execute(self.lun, command, data, direction)?;
            match block_disposition(&completion, self.removable) {
                BlockDisposition::Success => return Ok(()),
                BlockDisposition::Fail => return Err(BlockError::Eio),
                BlockDisposition::Retry { delay_ms } if retries < DEFAULT_RETRIES => {
                    retries += 1;
                    if delay_ms != 0 { self.transport.retry_delay(delay_ms)?; }
                }
                BlockDisposition::Retry { .. } => return Err(BlockError::Eio),
            }
        }
    }

    fn transfer(&self, request: &mut BlockRequest, write: bool) -> KResult<()> {
        let bytes = (request.len_blocks as usize).checked_mul(self.block_size as usize).ok_or(BlockError::Einval)?;
        if request.buffer.len() != bytes { return Err(BlockError::Einval); }
        if request.len_blocks == 0 { return Ok(()); }
        let command = self.cdb(write, request.start_block, request.len_blocks)?;
        self.execute_block(&command, &mut request.buffer, if write { DataDirection::ToDevice } else { DataDirection::FromDevice })
    }

    pub(crate) fn sg_io_max_transfer_bytes(&self) -> Option<usize> { self.transport.sg_io_max_transfer_bytes() }

    pub(crate) fn sg_io_max_cdb_bytes(&self) -> usize { self.transport.sg_io_max_cdb_bytes() }

    pub(crate) fn execute_sg_io(&self, command: &Command, data: &mut [u8], direction: DataDirection,
                                 timeout_ms: u32) -> KResult<CommandCompletion> {
        self.transport.execute_with_timeout(self.lun, command, data, direction, timeout_ms)
    }
}

impl BlockDevice for Disk {
    fn block_size(&self) -> u32 { self.block_size }
    fn queue_limits(&self) -> KResult<QueueLimits> {
        self.transport.queue_limits_for(self.lun, self.block_size)
    }
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
        let command = Command::new(&[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0])?;
        self.execute_block(&command, &mut [], DataDirection::None)
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
    publish_lun_with_media(transport, lun, block_size, capacity, false, serial)
}

/// Publish one scanned LUN while retaining whether INQUIRY marked its medium
/// removable. This state controls the Linux unit-attention retry rule.
/// # C: O(registry publication)
pub(crate) fn publish_lun_with_media(transport: Arc<dyn Transport>, lun: Lun, block_size: u32, capacity: u64,
                                     removable: bool, serial: Option<&str>) -> Option<block::ScsiDiskName> {
    let disk = Disk::new_with_media(transport, lun, block_size, capacity, removable).ok()?;
    let name = block::reserve_scsi_disk_name()?;
    let index = block::registry::register_with_driver(
        block::registry::BlockDriver::fixed("sd", block::uapi::SCSI_DISK_MAJOR), name.as_str(), serial, disk.clone());
    if index == 0 { return None; }
    let Some(dev_t) = block::registry::dev_t_of(name.as_str(), index) else {
        let _ = block::registry::unregister(name.as_str());
        return None;
    };
    if !crate::sg::register_target(dev_t, disk) {
        let _ = block::registry::unregister(name.as_str());
        return None;
    }
    Some(name)
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
