//! Shared SCSI command and disk mid-layer.
//!
//! The reference design separates transport command execution from `sd`
//! block-device publication. Keeping the same boundary prevents USB, SATA,
//! and future virtio-SCSI paths from each owning
//! subtly different READ/WRITE CDB construction and `sd*` registration.

#![no_std]

extern crate alloc;
#[cfg(test)] extern crate std;

use alloc::sync::Arc;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult, QueueLimits};

pub const READ_10: u8 = 0x28;
pub const WRITE_10: u8 = 0x2a;
pub const READ_CAPACITY_10: u8 = 0x25;
pub const SYNCHRONIZE_CACHE_10: u8 = 0x35;
pub const READ_16: u8 = 0x88;
pub const WRITE_16: u8 = 0x8a;
pub const SERVICE_ACTION_IN_16: u8 = 0x9e;
pub const READ_CAPACITY_16: u8 = 0x10;
pub const TEST_UNIT_READY: u8 = 0x00;

/// Direction a transport observes for one SCSI command. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataDirection { None, FromDevice, ToDevice }

/// A bounded SCSI CDB. The mid-layer owns its bytes, so a transport never
/// receives a pointer into a transient block request. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Command { bytes: [u8; 16], len: u8 }

impl Command {
    /// Make a CDB from its exact wire bytes. # C: O(CDB bytes)
    pub fn new(bytes: &[u8]) -> KResult<Self> {
        if bytes.is_empty() || bytes.len() > 16 { return Err(BlockError::Einval); }
        let mut cdb = [0u8; 16];
        cdb[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: cdb, len: bytes.len() as u8 })
    }
    /// Full CDB wire bytes, excluding the zero-filled tail. # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes[..self.len as usize] }
    /// Operation code. # C: O(1)
    pub fn opcode(&self) -> u8 { self.bytes[0] }
}

/// Transport endpoint below the common SCSI queue. Implementations own USB
/// BOT, ATA translation, virtio-SCSI, or a test backing; the caller supplies
/// a fully formed CDB and one contiguous data payload. # C: one command
pub trait Transport: Send + Sync {
    fn execute(&self, command: &Command, data: &mut [u8], direction: DataDirection) -> KResult<()>;
    /// Queue facts a transport can establish during discovery. The conservative
    /// default preserves logical-sector alignment without inventing cache or
    /// discard guarantees. # C: O(1)
    fn queue_limits(&self, block_size: u32) -> KResult<QueueLimits> {
        QueueLimits::for_logical_block_size(block_size)
    }
}

/// The `sd`-style block device above a SCSI transport. # C: O(1) construction
pub struct Disk {
    transport: Arc<dyn Transport>,
    block_size: u32,
    capacity: u64,
}

impl Disk {
    /// Build one disk after discovery has established its capacity and sector
    /// size. # C: O(1)
    pub fn new(transport: Arc<dyn Transport>, block_size: u32, capacity: u64) -> KResult<Arc<Self>> {
        if capacity == 0 || !block_size.is_power_of_two() || block_size < 512 { return Err(BlockError::Einval); }
        Ok(Arc::new(Self { transport, block_size, capacity }))
    }

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
        self.transport.execute(&command, &mut request.buffer,
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
        self.transport.execute(&Command::new(&[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0])?,
                               &mut [], DataDirection::None)
    }
}

/// Adapter for transports that already implement the block contract (libata
/// in this tree). It is deliberately below [`Disk`], so publication and CDB
/// semantics remain common even while the low-level controller migrates.
pub struct BlockTransport { inner: Arc<dyn BlockDevice> }

impl BlockTransport {
    /// Wrap one physical block endpoint as a SCSI command transport. # C: O(1)
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
        let mut request = if write {
            BlockRequest::new_write(lba, blocks, data.to_vec())
        } else {
            BlockRequest::new_read(lba, blocks, self.inner.block_size())
        };
        self.inner.submit_sync(&mut request)?;
        if !write { data.copy_from_slice(&request.buffer); }
        Ok(())
    }
}

impl Transport for BlockTransport {
    fn execute(&self, command: &Command, data: &mut [u8], direction: DataDirection) -> KResult<()> {
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

/// Publish a SCSI disk through the shared `sd*` namespace. # C: O(registry publication)
pub fn publish(transport: Arc<dyn Transport>, block_size: u32, capacity: u64, serial: Option<&str>) -> Option<block::ScsiDiskName> {
    let disk = Disk::new(transport, block_size, capacity).ok()?;
    let name = block::reserve_scsi_disk_name()?;
    let index = block::registry::register_with_driver(
        block::registry::BlockDriver::fixed("sd", block::uapi::SCSI_DISK_MAJOR), name.as_str(), serial, disk);
    (index != 0).then_some(name)
}

/// Publish an existing physical endpoint through the SCSI mid-layer. # C: O(registry publication)
pub fn publish_block_transport(inner: Arc<dyn BlockDevice>, serial: Option<&str>) -> Option<block::ScsiDiskName> {
    let block_size = inner.block_size();
    let capacity = inner.capacity_blocks();
    publish(BlockTransport::new(inner), block_size, capacity, serial)
}

/// SCSI has no global queue to start; host transports publish disks as they
/// discover LUNs. This explicit boot hook documents that ordering. # C: O(1)
pub fn init() {}

#[cfg(test)]
mod tests {
    use super::*;
    use sync::TaskList;

    #[test]
    fn shared_disk_translates_read_write_and_flush() {
        let backing: Arc<dyn BlockDevice> = block::MemDisk::<TaskList>::new(512, 32);
        let disk = Disk::new(BlockTransport::new(backing), 512, 32).expect("disk");
        let mut write = BlockRequest::new_write(3, 2, alloc::vec![0x5a; 1024]);
        disk.submit_sync(&mut write).expect("write");
        let mut read = BlockRequest::new_read(3, 2, 512);
        disk.submit_sync(&mut read).expect("read");
        assert_eq!(read.buffer, alloc::vec![0x5a; 1024]);
        disk.flush().expect("flush");
    }

    #[test]
    fn block_transport_reports_capacity_16() {
        let backing: Arc<dyn BlockDevice> = block::MemDisk::<TaskList>::new(4096, 11);
        let transport = BlockTransport::new(backing);
        let command = Command::new(&[SERVICE_ACTION_IN_16, READ_CAPACITY_16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).expect("cdb");
        let mut data = [0u8; 32];
        transport.execute(&command, &mut data, DataDirection::FromDevice).expect("capacity");
        assert_eq!(u64::from_be_bytes(data[..8].try_into().expect("last lba")), 10);
        assert_eq!(u32::from_be_bytes(data[8..12].try_into().expect("block size")), 4096);

        let mut short = [0u8; 8];
        transport.execute(&Command::new(&[READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0]).expect("short cdb"),
            &mut short, DataDirection::FromDevice).expect("short capacity");
        assert_eq!(u32::from_be_bytes(short[..4].try_into().expect("short last lba")), 10);
        assert_eq!(u32::from_be_bytes(short[4..8].try_into().expect("short block size")), 4096);
    }
}
