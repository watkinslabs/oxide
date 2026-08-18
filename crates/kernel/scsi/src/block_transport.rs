//! SCSI adapter for an endpoint that already implements the block contract.

extern crate alloc;

use alloc::sync::Arc;
use block::{BlockDevice, BlockError, BlockRequest, KResult, QueueLimits};

use crate::{Command, DataDirection, Lun, Transport, READ_10, READ_16, READ_CAPACITY_10, READ_CAPACITY_16,
    SERVICE_ACTION_IN_16, SYNCHRONIZE_CACHE_10, TEST_UNIT_READY, WRITE_10, WRITE_16};

/// Adapter for transports that already implement the block contract (libata
/// in this tree). It remains below [`crate::Disk`], so publication and CDB
/// semantics stay common while the low-level controller migrates. # C: O(1)
pub struct BlockTransport { inner: Arc<dyn BlockDevice> }

impl BlockTransport {
    /// Wrap one physical block endpoint as a single-LUN SCSI transport. # C: O(1)
    pub fn new(inner: Arc<dyn BlockDevice>) -> Arc<Self> { Arc::new(Self { inner }) }

    fn rw(&self, command: &Command, data: &mut [u8], write: bool) -> KResult<()> {
        let cdb = command.bytes();
        let (lba, blocks) = match command.opcode() {
            READ_10 | WRITE_10 if cdb.len() == 10 => (
                u64::from(u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]])),
                u32::from(u16::from_be_bytes([cdb[7], cdb[8]]))),
            READ_16 | WRITE_16 if cdb.len() == 16 => (
                u64::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5], cdb[6], cdb[7], cdb[8], cdb[9]]),
                u32::from_be_bytes([cdb[10], cdb[11], cdb[12], cdb[13]])),
            _ => return Err(BlockError::Einval),
        };
        let bytes = (blocks as usize).checked_mul(self.inner.block_size() as usize).ok_or(BlockError::Einval)?;
        if data.len() != bytes { return Err(BlockError::Einval); }
        let mut request = if write { BlockRequest::new_write(lba, blocks, data.to_vec()) }
            else { BlockRequest::new_read(lba, blocks, self.inner.block_size()) };
        self.inner.submit_sync(&mut request)?;
        if !write { data.copy_from_slice(&request.buffer); }
        Ok(())
    }
}

impl Transport for BlockTransport {
    fn execute(&self, lun: Lun, command: &Command, data: &mut [u8], direction: DataDirection) -> KResult<()> {
        if lun != Lun::ZERO { return Err(BlockError::Enxio); }
        match (command.opcode(), direction) {
            (TEST_UNIT_READY, DataDirection::None) => Ok(()),
            (SYNCHRONIZE_CACHE_10, DataDirection::None) => self.inner.flush(),
            (READ_10 | READ_16, DataDirection::FromDevice) => self.rw(command, data, false),
            (WRITE_10 | WRITE_16, DataDirection::ToDevice) => self.rw(command, data, true),
            (READ_CAPACITY_10, DataDirection::FromDevice) => {
                if data.len() < 8 { return Err(BlockError::Einval); }
                data.fill(0);
                let last_lba = self.inner.capacity_blocks().saturating_sub(1).min(u64::from(u32::MAX)) as u32;
                data[..4].copy_from_slice(&last_lba.to_be_bytes());
                data[4..8].copy_from_slice(&self.inner.block_size().to_be_bytes());
                Ok(())
            }
            (SERVICE_ACTION_IN_16, DataDirection::FromDevice) if command.bytes().get(1) == Some(&READ_CAPACITY_16) => {
                if data.len() < 12 { return Err(BlockError::Einval); }
                data.fill(0);
                data[..8].copy_from_slice(&self.inner.capacity_blocks().saturating_sub(1).to_be_bytes());
                data[8..12].copy_from_slice(&self.inner.block_size().to_be_bytes());
                Ok(())
            }
            _ => Err(BlockError::Eopnotsupp),
        }
    }

    fn queue_limits(&self, _block_size: u32) -> KResult<QueueLimits> { self.inner.queue_limits() }
}
