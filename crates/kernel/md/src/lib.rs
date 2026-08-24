//! Multiple-device (MD) block mapping core.
//!
//! Array geometry remains immutable once published while lifecycle admission
//! owns the writable/read-only state; each I/O is split at exactly the
//! component or stripe boundary before being submitted to a member device.

#![no_std]

extern crate alloc;
#[cfg(test)] extern crate std;

// Module manifest: superblock owns v1 metadata validation; assembly owns data
// views and personality construction; lifecycle owns write-state admission;
// control owns ioctl state; autostart owns boot-time discovery.
mod superblock;
mod assembly;
mod lifecycle;
mod control;
mod autostart;
pub mod uapi;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult, QueueLimits};
use sync::{Devices as MdStateClass, Spinlock};

pub use superblock::{MetadataVersion, Superblock, read_superblock};
pub use assembly::assemble;
pub use control::{array_info, disk_info, is_md_device, restart_array_read_write, set_array_info, set_disk_faulty, stop_array, stop_array_read_only};

/// Linux's fixed block major for MD arrays. # C: O(1)
pub const MD_MAJOR: u32 = 9;
const MD_DRIVER: block::registry::BlockDriver = block::registry::BlockDriver::unpartitioned_fixed("md", MD_MAJOR);

/// The mapping personality an immutable MD array exposes. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Level {
    Linear,
    Raid0 { chunk_blocks: u32 },
    Raid1,
}

/// An MD array with immutable geometry over live block components. # C: O(1) construction
pub struct Array {
    level: Level,
    members: Vec<Arc<dyn BlockDevice>>,
    block_size: u32,
    capacity: u64,
    metadata: Option<control::Metadata>,
    metadata_members: Vec<Arc<dyn BlockDevice>>,
    metadata_version: Option<MetadataVersion>,
    metadata_events: Spinlock<u64, MdStateClass>,
    lifecycle: lifecycle::State,
    faulty: Spinlock<Vec<bool>, MdStateClass>,
}

impl Array {
    /// Validate and create an MD linear array. # C: O(members)
    pub fn linear(members: Vec<Arc<dyn BlockDevice>>) -> KResult<Arc<Self>> {
        Self::new(Level::Linear, members, None)
    }

    /// Validate and create a chunk-striped RAID0 array. # C: O(members)
    pub fn raid0(members: Vec<Arc<dyn BlockDevice>>, chunk_blocks: u32) -> KResult<Arc<Self>> {
        Self::new(Level::Raid0 { chunk_blocks }, members, None)
    }

    /// Validate and create a mirrored RAID1 array. Reads try surviving members
    /// in order; writes and flushes visit every member. # C: O(members)
    pub fn raid1(members: Vec<Arc<dyn BlockDevice>>) -> KResult<Arc<Self>> {
        Self::new(Level::Raid1, members, None)
    }

    pub(crate) fn from_metadata(level: Level, members: Vec<Arc<dyn BlockDevice>>, metadata: control::Metadata,
                                metadata_members: Vec<Arc<dyn BlockDevice>>, version: MetadataVersion, events: u64) -> KResult<Arc<Self>> {
        Self::new_with_metadata(level, members, Some(metadata), metadata_members, Some(version), events)
    }

    fn new(level: Level, members: Vec<Arc<dyn BlockDevice>>, metadata: Option<control::Metadata>) -> KResult<Arc<Self>> {
        Self::new_with_metadata(level, members, metadata, Vec::new(), None, 0)
    }

    fn new_with_metadata(level: Level, members: Vec<Arc<dyn BlockDevice>>, metadata: Option<control::Metadata>,
                         metadata_members: Vec<Arc<dyn BlockDevice>>, metadata_version: Option<MetadataVersion>, metadata_events: u64) -> KResult<Arc<Self>> {
        let Some(first) = members.first() else { return Err(BlockError::Einval); };
        let block_size = first.block_size();
        if members.iter().any(|member| member.block_size() != block_size || member.capacity_blocks() == 0) {
            return Err(BlockError::Einval);
        }
        let capacity = match level {
            Level::Linear => members.iter().try_fold(0u64, |total, member| total.checked_add(member.capacity_blocks()))
                .ok_or(BlockError::Einval)?,
            Level::Raid0 { chunk_blocks } => {
                if chunk_blocks == 0 { return Err(BlockError::Einval); }
                let smallest = members.iter().map(|member| member.capacity_blocks()).min().ok_or(BlockError::Einval)?;
                smallest.checked_div(u64::from(chunk_blocks)).and_then(|chunks|
                    chunks.checked_mul(u64::from(chunk_blocks))).and_then(|per_member|
                    per_member.checked_mul(members.len() as u64)).ok_or(BlockError::Einval)?
            }
            Level::Raid1 => members.iter().map(|member| member.capacity_blocks()).min().ok_or(BlockError::Einval)?,
        };
        if capacity == 0 { return Err(BlockError::Einval); }
        Ok(Arc::new(Self { level, faulty: Spinlock::new(vec![false; members.len()]), members,
            block_size, capacity, metadata, metadata_members, metadata_version, metadata_events: Spinlock::new(metadata_events), lifecycle: lifecycle::State::new() }))
    }

    /// Array personality. # C: O(1)
    pub fn level(&self) -> Level { self.level }

    /// Begin the read-only transition. # C: O(1)
    pub(crate) fn begin_read_only(&self) -> KResult<()> { self.lifecycle.begin_read_only() }
    /// Begin a final stop from writable or read-only service. # C: O(1)
    pub(crate) fn begin_stop(&self) -> KResult<lifecycle::StopStart> { self.lifecycle.begin_stop() }
    /// Wait for modifying requests admitted before the seal. # C: O(in-flight writes)
    pub(crate) fn wait_for_writers(&self) { self.lifecycle.wait_for_writers(); }
    /// Finish the read-only transition after the final cache drain. # C: O(in-flight writes)
    pub(crate) fn finish_read_only(&self) -> KResult<()> { self.lifecycle.finish_read_only() }
    /// Cancel a failed read-only transition. # C: O(1)
    pub(crate) fn cancel_read_only(&self) { self.lifecycle.cancel_read_only(); }
    /// Return the array to writable service. # C: O(1)
    pub(crate) fn restart_read_write(&self) -> KResult<()> { self.lifecycle.restart_read_write() }

    /// Mark one assembled member faulty using its canonical Linux device number.
    /// The state transition is owned by the array, so reporting and I/O observe
    /// one value. A RAID1 array must retain one working member. # C: O(members)
    pub fn set_disk_faulty(&self, dev_t: u32) -> KResult<()> {
        let metadata = self.metadata.as_ref().ok_or(BlockError::Enxio)?;
        let member = metadata.members.iter().position(|member|
            block::registry::encode_dev(member.number_dev.major, member.number_dev.minor) == dev_t)
            .ok_or(BlockError::Enxio)?;
        let member_number = metadata.members[member].number;
        {
            let faulty = self.faulty.lock();
            if faulty[member] { return Ok(()); }
            if self.level == Level::Raid1 && faulty.iter().filter(|faulty| !**faulty).count() <= 1 { return Err(BlockError::Ebusy); }
        }
        let events = { let current = *self.metadata_events.lock(); current.wrapping_add(1) };
        if let Some(version) = self.metadata_version {
            for (index, disk) in self.metadata_members.iter().enumerate() {
                if index != member && !self.member_faulty(index) {
                    crate::superblock::write_faulty(disk.as_ref(), version, member_number, events)?;
                }
            }
        }
        self.faulty.lock()[member] = true;
        *self.metadata_events.lock() = events;
        Ok(())
    }

    pub(crate) fn member_faulty(&self, member: usize) -> bool { self.faulty.lock().get(member).copied().unwrap_or(true) }
    pub(crate) fn failed_members(&self) -> usize { self.faulty.lock().iter().filter(|faulty| **faulty).count() }

    fn validate(&self, request: &BlockRequest) -> KResult<()> {
        let end = request.start_block.checked_add(u64::from(request.len_blocks)).ok_or(BlockError::Einval)?;
        if end > self.capacity { return Err(BlockError::Eio); }
        let bytes = (request.len_blocks as usize).checked_mul(self.block_size as usize).ok_or(BlockError::Einval)?;
        match request.op {
            BlockOp::Read | BlockOp::Write if request.buffer.len() != bytes => Err(BlockError::Einval),
            BlockOp::WriteZeroes { .. } | BlockOp::Discard | BlockOp::Flush if !request.buffer.is_empty() => Err(BlockError::Einval),
            _ => Ok(()),
        }
    }

    fn child_request(&self, source: &BlockRequest, start_block: u64, len_blocks: u32, byte_offset: usize) -> KResult<BlockRequest> {
        let bytes = (len_blocks as usize).checked_mul(self.block_size as usize).ok_or(BlockError::Einval)?;
        let buffer = match source.op {
            BlockOp::Read => vec![0u8; bytes],
            BlockOp::Write => source.buffer.get(byte_offset..byte_offset.checked_add(bytes).ok_or(BlockError::Einval)?)
                .ok_or(BlockError::Einval)?.to_vec(),
            BlockOp::WriteZeroes { .. } | BlockOp::Discard | BlockOp::Flush => Vec::new(),
        };
        Ok(BlockRequest { op: source.op, start_block, len_blocks, buffer, ioprio: source.ioprio,
            flags: source.flags, durability: source.durability, polled: source.polled, crypt: source.crypt.clone(),
            writeback: source.writeback })
    }

    fn submit_piece(&self, member: usize, member_block: u64, request: &mut BlockRequest,
                    blocks: u32, byte_offset: usize) -> KResult<()> {
        if self.member_faulty(member) { return Err(BlockError::Eio); }
        let mut child = self.child_request(request, member_block, blocks, byte_offset)?;
        self.members[member].submit_sync(&mut child)?;
        if request.op == BlockOp::Read {
            let bytes = child.buffer.len();
            request.buffer[byte_offset..byte_offset + bytes].copy_from_slice(&child.buffer);
        }
        Ok(())
    }

    fn submit_linear(&self, request: &mut BlockRequest) -> KResult<()> {
        let mut remaining = request.len_blocks;
        let mut logical = request.start_block;
        let mut byte_offset = 0usize;
        while remaining != 0 {
            let mut base = 0u64;
            let mut found = None;
            for (index, member) in self.members.iter().enumerate() {
                let end = base.checked_add(member.capacity_blocks()).ok_or(BlockError::Einval)?;
                if logical < end { found = Some((index, logical - base, end - logical)); break; }
                base = end;
            }
            let (member, member_block, available) = found.ok_or(BlockError::Eio)?;
            let blocks = remaining.min(available.try_into().unwrap_or(u32::MAX));
            self.submit_piece(member, member_block, request, blocks, byte_offset)?;
            remaining -= blocks;
            logical += u64::from(blocks);
            byte_offset += blocks as usize * self.block_size as usize;
        }
        Ok(())
    }

    fn submit_raid0(&self, request: &mut BlockRequest, chunk_blocks: u32) -> KResult<()> {
        let mut remaining = request.len_blocks;
        let mut logical = request.start_block;
        let mut byte_offset = 0usize;
        while remaining != 0 {
            let chunk = u64::from(chunk_blocks);
            let stripe = logical / chunk;
            let member = (stripe % self.members.len() as u64) as usize;
            let member_block = (stripe / self.members.len() as u64).checked_mul(chunk)
                .and_then(|base| base.checked_add(logical % chunk)).ok_or(BlockError::Einval)?;
            let until_boundary = chunk - logical % chunk;
            let blocks = remaining.min(until_boundary.try_into().unwrap_or(u32::MAX));
            self.submit_piece(member, member_block, request, blocks, byte_offset)?;
            remaining -= blocks;
            logical += u64::from(blocks);
            byte_offset += blocks as usize * self.block_size as usize;
        }
        Ok(())
    }

    fn submit_raid1(&self, request: &mut BlockRequest) -> KResult<()> {
        match request.op {
            BlockOp::Read => {
                let mut failure = BlockError::Eio;
                for member in 0..self.members.len() {
                    match self.submit_piece(member, request.start_block, request, request.len_blocks, 0) {
                        Ok(()) => return Ok(()),
                        Err(error) => failure = error,
                    }
                }
                Err(failure)
            }
            BlockOp::Flush => self.flush(),
            _ => {
                let mut failure = None;
                for member in 0..self.members.len() {
                    if self.member_faulty(member) { continue; }
                    if let Err(error) = self.submit_piece(member, request.start_block, request, request.len_blocks, 0) {
                        failure.get_or_insert(error);
                    }
                }
                failure.map_or(Ok(()), Err)
            }
        }
    }
}

impl BlockDevice for Array {
    fn block_size(&self) -> u32 { self.block_size }
    fn queue_limits(&self) -> KResult<QueueLimits> { QueueLimits::for_logical_block_size(self.block_size) }
    fn capacity_blocks(&self) -> u64 { self.capacity }
    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        let _write = self.lifecycle.admit(request)?;
        self.validate(request)?;
        match self.level {
            Level::Linear => self.submit_linear(request),
            Level::Raid0 { chunk_blocks } => self.submit_raid0(request, chunk_blocks),
            Level::Raid1 => self.submit_raid1(request),
        }
    }
    fn flush(&self) -> KResult<()> {
        let mut failure = None;
        for (index, member) in self.members.iter().enumerate() {
            if self.member_faulty(index) { continue; }
            if let Err(error) = member.flush() { failure.get_or_insert(error); }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn named_minor(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("md")?;
    if digits.is_empty() { return None; }
    digits.bytes().try_fold(0u32, |minor, digit| {
        if !digit.is_ascii_digit() { return None; }
        minor.checked_mul(10)?.checked_add(u32::from(digit - b'0'))
    })
}

/// Publish an immutable MD array as `/dev/mdN` at the matching fixed `9:N`
/// device number. # C: O(registry publication)
pub fn publish(name: &str, array: Arc<Array>) -> u32 {
    let Some(minor) = named_minor(name) else { return 0; };
    let existed = block::registry::by_name(name).is_some();
    let device: Arc<dyn BlockDevice> = array.clone();
    let index = block::registry::register_with_driver_at(MD_DRIVER, name, name, None, Some(minor), device);
    if index != 0 && !existed { control::publish(minor, &array); }
    index
}

/// MD has no global queues to start; array construction is explicitly owned by
/// its caller. This boot hook keeps its lifecycle visible in the rootfs phase.
/// # C: O(1)
pub fn init() { autostart::init(); }

#[cfg(test)]
mod tests {
    use super::*;
    use sync::TaskList;

    fn disk(blocks: u64) -> Arc<dyn BlockDevice> { block::MemDisk::<TaskList>::new(512, blocks) }

    #[test]
    fn linear_crosses_member_boundary() {
        let array = Array::linear(vec![disk(4), disk(4)]).expect("linear");
        let mut write = BlockRequest::new_write(3, 2, vec![0x41; 1024]);
        array.submit_sync(&mut write).expect("write");
        let mut read = BlockRequest::new_read(3, 2, 512);
        array.submit_sync(&mut read).expect("read");
        assert_eq!(read.buffer, vec![0x41; 1024]);
        assert_eq!(array.capacity_blocks(), 8);
    }

    #[test]
    fn raid0_interleaves_chunks() {
        let array = Array::raid0(vec![disk(8), disk(8)], 2).expect("raid0");
        let mut write = BlockRequest::new_write(0, 6, (0..6).flat_map(|block| vec![block as u8; 512]).collect());
        array.submit_sync(&mut write).expect("write");
        let mut read = BlockRequest::new_read(0, 6, 512);
        array.submit_sync(&mut read).expect("read");
        for block in 0..6 { assert_eq!(&read.buffer[block * 512..(block + 1) * 512], vec![block as u8; 512]); }
    }

    #[test]
    fn raid1_writes_all_members() {
        let first = disk(8);
        let second = disk(8);
        let array = Array::raid1(vec![Arc::clone(&first), Arc::clone(&second)]).expect("raid1");
        let mut write = BlockRequest::new_write(1, 1, vec![0x77; 512]);
        array.submit_sync(&mut write).expect("write");
        for member in [first, second] {
            let mut read = BlockRequest::new_read(1, 1, 512);
            member.submit_sync(&mut read).expect("member read");
            assert_eq!(read.buffer, vec![0x77; 512]);
        }
    }

    #[test]
    fn md_name_selects_its_linux_minor() {
        assert_eq!(named_minor("md0"), Some(0));
        assert_eq!(named_minor("md4096"), Some(4096));
        assert_eq!(named_minor("md"), None);
        assert_eq!(named_minor("md_raid"), None);
        assert_eq!(named_minor("array0"), None);
    }
}
