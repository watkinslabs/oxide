//! SCSI generic v3 ABI, command admission, and published-disk lookup.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use block::{BlockError, KResult};
use sync::{Devices, Spinlock};

use crate::{Command, CommandCompletion, DataDirection, Disk};

/// Linux SCSI generic v3 `SG_IO` request number. # C: O(1)
pub const SG_IO: u64 = 0x2285;
/// Native 64-bit `struct sg_io_hdr` size on both supported architectures. # C: O(1)
pub const SG_IO_HDR_BYTES: usize = 88;
/// Default SG_IO timeout, in milliseconds. # C: O(1)
pub const DEFAULT_TIMEOUT_MS: u32 = 60_000;
/// Linux's minimum accepted SG_IO timeout, in milliseconds. # C: O(1)
pub const MIN_TIMEOUT_MS: u32 = 7_000;

const SG_INTERFACE_ID: i32 = b'S' as i32;
const SG_DXFER_TO_DEV: i32 = -2;
const SG_DXFER_FROM_DEV: i32 = -3;
const SG_DXFER_TO_FROM_DEV: i32 = -4;
const SG_INFO_CHECK: u32 = 0x1;
const DRIVER_SENSE: u16 = 0x08;

/// One native 64-bit `sg_io_hdr` image.  Keeping the original bytes preserves
/// every input-only field and padding when the completed header is copied back.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SgHeader { bytes: [u8; SG_IO_HDR_BYTES] }

impl SgHeader {
    /// Decode the native 64-bit userspace ABI. # C: O(1)
    pub const fn from_bytes(bytes: [u8; SG_IO_HDR_BYTES]) -> Self { Self { bytes } }

    /// Completed header image for copy-back. # C: O(1)
    pub const fn bytes(&self) -> &[u8; SG_IO_HDR_BYTES] { &self.bytes }

    /// Required SCSI generic interface id. # C: O(1)
    pub fn interface_id(&self) -> i32 { i32::from_ne_bytes(self.bytes[0..4].try_into().expect("fixed field")) }
    /// Requested data-transfer direction. # C: O(1)
    pub fn direction_raw(&self) -> i32 { i32::from_ne_bytes(self.bytes[4..8].try_into().expect("fixed field")) }
    /// CDB byte count. # C: O(1)
    pub const fn cmd_len(&self) -> u8 { self.bytes[8] }
    /// Maximum sense bytes requested by the caller. # C: O(1)
    pub const fn mx_sb_len(&self) -> u8 { self.bytes[9] }
    /// Number of native `sg_iovec` elements, zero for one flat buffer. # C: O(1)
    pub fn iovec_count(&self) -> u16 { u16::from_ne_bytes(self.bytes[10..12].try_into().expect("fixed field")) }
    /// Requested data length. # C: O(1)
    pub fn dxfer_len(&self) -> u32 { u32::from_ne_bytes(self.bytes[12..16].try_into().expect("fixed field")) }
    /// Flat data pointer or native `sg_iovec *`. # C: O(1)
    pub fn dxferp(&self) -> u64 { u64::from_ne_bytes(self.bytes[16..24].try_into().expect("fixed field")) }
    /// CDB pointer. # C: O(1)
    pub fn cmdp(&self) -> u64 { u64::from_ne_bytes(self.bytes[24..32].try_into().expect("fixed field")) }
    /// Sense-buffer pointer. # C: O(1)
    pub fn sbp(&self) -> u64 { u64::from_ne_bytes(self.bytes[32..40].try_into().expect("fixed field")) }
    /// Caller timeout after Linux's default/minimum normalization. # C: O(1)
    pub fn timeout_ms(&self) -> u32 {
        let requested = u32::from_ne_bytes(self.bytes[40..44].try_into().expect("fixed field"));
        if requested == 0 { DEFAULT_TIMEOUT_MS } else { core::cmp::max(requested, MIN_TIMEOUT_MS) }
    }

    /// Translate a non-empty data transfer's direction. # C: O(1)
    pub fn direction(&self) -> Option<DataDirection> {
        match self.direction_raw() {
            SG_DXFER_TO_DEV => Some(DataDirection::ToDevice),
            SG_DXFER_FROM_DEV | SG_DXFER_TO_FROM_DEV => Some(DataDirection::FromDevice),
            _ => None,
        }
    }

    /// Test Linux's required interface marker. # C: O(1)
    pub fn has_interface_id(&self) -> bool { self.interface_id() == SG_INTERFACE_ID }

    /// Write Linux SG_IO completion fields while preserving the caller's
    /// input fields. # C: O(sense bytes)
    pub fn complete(&mut self, completion: CommandCompletion, extra_resid: u32, sense_written: u8,
                    duration_ms: u32) {
        self.bytes[64] = completion.status();
        self.bytes[65] = (completion.status() >> 1) & 0x7f;
        self.bytes[66] = 0;
        self.bytes[67] = sense_written;
        self.bytes[68..70].copy_from_slice(&completion.host_status().to_ne_bytes());
        let driver = if completion.status() == 0x02 { DRIVER_SENSE } else { completion.driver_status() };
        self.bytes[70..72].copy_from_slice(&driver.to_ne_bytes());
        let resid = completion.resid().saturating_add(extra_resid).min(i32::MAX as u32) as i32;
        self.bytes[72..76].copy_from_slice(&resid.to_ne_bytes());
        self.bytes[76..80].copy_from_slice(&duration_ms.to_ne_bytes());
        let info = (completion.status() != 0 || completion.host_status() != 0 || driver != 0) as u32 * SG_INFO_CHECK;
        self.bytes[80..84].copy_from_slice(&info.to_ne_bytes());
    }
}

/// Decide whether the reference permits a CDB from this file description.
/// Raw-I/O capability admits every CDB; otherwise only the reference's
/// read-safe set is permitted from a read-only description. # C: O(1)
pub fn command_allowed(command: &Command, open_for_write: bool, raw_io: bool) -> bool {
    if raw_io { return true; }
    match command.opcode() {
        0x00 | 0x03 | 0x08 | 0x28 | 0xa8 | 0x88 | 0x3c | 0x37 | 0x25 | 0x3e | 0x12 | 0x1a | 0x5a
        | 0x4d | 0x1b | 0x2f | 0x8f | 0xa0 | 0x9e | 0x1c | 0xa3 | 0x5c | 0xbc | 0x45 | 0x47 | 0x48
        | 0x4b | 0xbe | 0xb9 | 0x51 | 0xad | 0x44 | 0x52 | 0x42 | 0x43 | 0xa4 | 0xba | 0x46 | 0x23
        | 0x4a | 0xac | 0x2b | 0x4e | 0x95 => true,
        0x0a | 0x2a | 0x2e | 0xaa | 0xae | 0x8a | 0x3f | 0xea | 0x41 | 0x93 | 0x0d | 0x19 | 0x55
        | 0x15 | 0x4c | 0xa1 | 0x5b | 0x35 | 0x04 | 0x58 | 0x53 | 0xbf | 0xa2 | 0x54 | 0x5d | 0xbb
        | 0x1e | 0xa6 | 0xb6 | 0xa7 | 0x94 => open_for_write,
        _ => false,
    }
}

struct TargetRecord { dev_t: u32, disk: Arc<Disk> }
static TARGETS: Spinlock<Vec<TargetRecord>, Devices> = Spinlock::new(Vec::new());

/// An addressed SCSI disk retained by the shared mid-layer. # C: O(1)
#[derive(Clone)]
pub struct SgIoTarget { disk: Arc<Disk> }

impl SgIoTarget {
    /// `None` when this published SCSI disk is currently block-only. # C: O(1)
    pub fn max_transfer_bytes(&self) -> Option<usize> { self.disk.sg_io_max_transfer_bytes() }

    /// Largest raw CDB this target's transport can execute. # C: O(1)
    pub fn max_cdb_bytes(&self) -> usize { self.disk.sg_io_max_cdb_bytes() }

    /// Execute one pre-validated SG_IO CDB. # C: one command
    pub fn execute(&self, command: &Command, data: &mut [u8], direction: DataDirection,
                   timeout_ms: u32) -> KResult<CommandCompletion> {
        let max = self.max_transfer_bytes().ok_or(BlockError::Eopnotsupp)?;
        if command.bytes().len() > self.max_cdb_bytes() { return Err(BlockError::Einval); }
        if data.len() > max { return Err(BlockError::Eio); }
        self.disk.execute_sg_io(command, data, direction, timeout_ms)
    }
}

/// Resolve a block dev_t to the SCSI disk that published it. # C: O(disks)
pub fn sg_target(dev_t: u32) -> Option<SgIoTarget> {
    TARGETS.lock().iter().find(|entry| entry.dev_t == dev_t).map(|entry| SgIoTarget { disk: Arc::clone(&entry.disk) })
}

/// Register or replace the SCSI owner for a freshly published disk.  A failed
/// allocation lets publication roll back rather than exposing an sd node whose
/// SCSI command path has no owner. # C: O(disks)
pub(crate) fn register_target(dev_t: u32, disk: Arc<Disk>) -> bool {
    let mut targets = TARGETS.lock();
    if let Some(existing) = targets.iter_mut().find(|entry| entry.dev_t == dev_t) {
        existing.disk = disk;
        return true;
    }
    if targets.try_reserve(1).is_err() { return false; }
    targets.push(TargetRecord { dev_t, disk });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use block::{BlockError, KResult, QueueLimits};

    struct CheckConditionTransport;

    impl crate::Transport for CheckConditionTransport {
        fn execute(&self, _lun: crate::Lun, _command: &Command, _data: &mut [u8],
                   _direction: DataDirection) -> KResult<CommandCompletion> {
            Ok(CommandCompletion::check_condition(3, &[0x70, 0, 5, 0x20]))
        }

        fn sg_io_max_transfer_bytes(&self) -> Option<usize> { Some(16) }

        fn queue_limits(&self, block_size: u32) -> KResult<QueueLimits> {
            QueueLimits::for_logical_block_size(block_size)
        }
    }

    #[test]
    fn header_keeps_native_64_bit_layout_and_updates_only_outputs() {
        let mut bytes = [0u8; SG_IO_HDR_BYTES];
        bytes[0..4].copy_from_slice(&(b'S' as i32).to_ne_bytes());
        bytes[4..8].copy_from_slice(&SG_DXFER_FROM_DEV.to_ne_bytes());
        bytes[8] = 6;
        bytes[9] = 4;
        bytes[12..16].copy_from_slice(&32u32.to_ne_bytes());
        let mut hdr = SgHeader::from_bytes(bytes);
        hdr.complete(CommandCompletion::check_condition(3, &[0x70, 0, 5, 1, 2]), 2, 4, 7);
        assert!(hdr.has_interface_id());
        assert_eq!(hdr.direction(), Some(DataDirection::FromDevice));
        assert_eq!(hdr.bytes()[64], 2);
        assert_eq!(hdr.bytes()[65], 1);
        assert_eq!(hdr.bytes()[67], 4);
        assert_eq!(i32::from_ne_bytes(hdr.bytes()[72..76].try_into().expect("resid")), 5);
        assert_eq!(u32::from_ne_bytes(hdr.bytes()[76..80].try_into().expect("duration")), 7);
        assert_eq!(u32::from_ne_bytes(hdr.bytes()[80..84].try_into().expect("info")), SG_INFO_CHECK);
    }

    #[test]
    fn permission_ladder_never_grants_an_unknown_cdb_without_rawio() {
        assert!(command_allowed(&Command::new(&[0x12, 0, 0, 0, 36, 0]).expect("inquiry"), false, false));
        assert!(!command_allowed(&Command::new(&[0x2a; 10]).expect("write"), false, false));
        assert!(command_allowed(&Command::new(&[0x2a; 10]).expect("write"), true, false));
        assert!(!command_allowed(&Command::new(&[0xff; 16]).expect("unknown"), true, false));
        assert!(command_allowed(&Command::new(&[0xff; 16]).expect("unknown"), false, true));
    }

    #[test]
    fn timeout_uses_reference_default_and_floor() {
        let mut bytes = [0u8; SG_IO_HDR_BYTES];
        let mut hdr = SgHeader::from_bytes(bytes);
        assert_eq!(hdr.timeout_ms(), DEFAULT_TIMEOUT_MS);
        bytes[40..44].copy_from_slice(&1u32.to_ne_bytes());
        hdr = SgHeader::from_bytes(bytes);
        assert_eq!(hdr.timeout_ms(), MIN_TIMEOUT_MS);
    }

    #[test]
    fn raw_target_keeps_check_condition_as_a_completion_and_enforces_its_bound() {
        let disk = Disk::new(Arc::new(CheckConditionTransport), crate::Lun::ZERO, 512, 1).expect("disk");
        let target = SgIoTarget { disk };
        let command = Command::new(&[0x12, 0, 0, 0, 36, 0]).expect("inquiry");
        let mut data = [0u8; 8];
        let completion = target.execute(&command, &mut data, DataDirection::FromDevice, 7_000).expect("completion");
        assert_eq!(completion.status(), 2);
        assert_eq!(completion.resid(), 3);
        assert_eq!(completion.sense(), &[0x70, 0, 5, 0x20]);
        let mut too_big = [0u8; 17];
        assert_eq!(target.execute(&command, &mut too_big, DataDirection::FromDevice, 7_000), Err(BlockError::Eio));
        let overlong = Command::new(&[0x12; 17]).expect("shared CDB bound");
        assert_eq!(target.execute(&overlong, &mut [], DataDirection::None, 7_000), Err(BlockError::Einval));
    }
}
