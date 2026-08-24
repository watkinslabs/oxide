//! SCSI addressing and transport execution boundary.

use block::{KResult, QueueLimits};

use crate::Command;

/// Direction a transport observes for one SCSI command. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataDirection { None, FromDevice, ToDevice }

/// Maximum fixed-format sense data retained by the common SCSI path.  This is
/// the Linux mid-layer's fixed per-command sense-buffer size. # C: O(1)
pub const SENSE_BYTES: usize = 96;

/// Completion facts returned by a transport.  A SCSI CHECK CONDITION is a
/// completed command, not a transport failure: SG_IO returns it in its header
/// and sense buffer while ordinary block I/O maps it to EIO. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CommandCompletion {
    status: u8,
    host_status: u16,
    driver_status: u16,
    resid: u32,
    sense: [u8; SENSE_BYTES],
    sense_len: u8,
}

impl CommandCompletion {
    /// A command that completed fully with GOOD status. # C: O(1)
    pub const fn good() -> Self {
        Self { status: 0, host_status: 0, driver_status: 0, resid: 0, sense: [0; SENSE_BYTES], sense_len: 0 }
    }

    /// A successful command that transferred only a prefix. # C: O(1)
    pub const fn good_with_resid(resid: u32) -> Self {
        Self { status: 0, host_status: 0, driver_status: 0, resid, sense: [0; SENSE_BYTES], sense_len: 0 }
    }

    /// Build a CHECK CONDITION completion carrying fixed- or descriptor-format
    /// sense data unchanged.
    /// # C: O(sense bytes)
    pub fn check_condition(resid: u32, sense: &[u8]) -> Self {
        let mut stored = [0; SENSE_BYTES];
        let len = core::cmp::min(stored.len(), sense.len());
        stored[..len].copy_from_slice(&sense[..len]);
        Self { status: 0x02, host_status: 0, driver_status: 0x08, resid, sense: stored, sense_len: len as u8 }
    }

    /// SCSI status byte. # C: O(1)
    pub const fn status(self) -> u8 { self.status }
    /// Host-adapter status for SG_IO. # C: O(1)
    pub const fn host_status(self) -> u16 { self.host_status }
    /// Driver status for SG_IO. # C: O(1)
    pub const fn driver_status(self) -> u16 { self.driver_status }
    /// Bytes not transferred. # C: O(1)
    pub const fn resid(self) -> u32 { self.resid }
    /// Retained request-sense bytes. # C: O(1)
    pub fn sense(&self) -> &[u8] { &self.sense[..self.sense_len as usize] }
    /// True only for a fully successful ordinary block command. # C: O(1)
    pub const fn is_good(self) -> bool {
        self.status == 0 && self.host_status == 0 && self.driver_status == 0 && self.resid == 0
    }
}

/// One logical unit number beneath a SCSI target. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Lun(u64);

impl Lun {
    /// The first LUN probed on every target. # C: O(1)
    pub const ZERO: Self = Self(0);

    /// Construct a protocol LUN value. # C: O(1)
    pub const fn new(value: u64) -> Self { Self(value) }

    /// Numeric protocol LUN value. # C: O(1)
    pub const fn value(self) -> u64 { self.0 }
}

/// Transport endpoint below the common SCSI queue. Implementations own USB
/// BOT, ATA translation, virtio-SCSI, or a test backing; the caller supplies
/// one fully formed CDB, one addressed LUN, and one contiguous data payload.
/// # C: one command
pub trait Transport: Send + Sync {
    /// Highest addressable LUN on this target. # C: O(1)
    fn max_lun(&self) -> Lun { Lun::ZERO }

    /// Execute one command for the addressed LUN. # C: one command
    fn execute(&self, lun: Lun, command: &Command, data: &mut [u8], direction: DataDirection) -> KResult<CommandCompletion>;

    /// Execute with an SG_IO timeout in milliseconds.  Legacy transports use
    /// their ordinary synchronous path; a hardware owner overrides this when
    /// it can carry the caller's timeout to its completion wait. # C: one command
    fn execute_with_timeout(&self, lun: Lun, command: &Command, data: &mut [u8], direction: DataDirection,
                            _timeout_ms: u32) -> KResult<CommandCompletion> {
        self.execute(lun, command, data, direction)
    }

    /// Wait before the common block path reissues a retryable completion.
    /// Hosts implement this only with a real process-context wait; the common
    /// layer deliberately has no scheduler dependency and must not spin.
    /// # C: one bounded wait
    fn retry_delay(&self, _delay_ms: u32) -> KResult<()> { Err(block::BlockError::Eopnotsupp) }

    /// Largest payload the transport can execute through SG_IO. `None` means
    /// this adapter is deliberately block-only and must not advertise raw CDB
    /// passthrough. # C: O(1)
    fn sg_io_max_transfer_bytes(&self) -> Option<usize> { None }

    /// Largest CDB this raw transport can execute.  The common 16-byte
    /// default preserves protocol adapters such as USB Bulk-Only. # C: O(1)
    fn sg_io_max_cdb_bytes(&self) -> usize { 16 }

    /// Queue facts a transport can establish during discovery. The conservative
    /// default preserves logical-sector alignment without inventing cache or
    /// discard guarantees. # C: O(1)
    fn queue_limits(&self, block_size: u32) -> KResult<QueueLimits> {
        QueueLimits::for_logical_block_size(block_size)
    }

    /// Queue facts for one addressed LUN. Adapters that discover cache state
    /// per target override this; the default preserves older transports.
    fn queue_limits_for(&self, _lun: Lun, block_size: u32) -> KResult<QueueLimits> {
        self.queue_limits(block_size)
    }
}
