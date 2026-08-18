//! SCSI addressing and transport execution boundary.

use block::{KResult, QueueLimits};

use crate::Command;

/// Direction a transport observes for one SCSI command. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataDirection { None, FromDevice, ToDevice }

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
    fn execute(&self, lun: Lun, command: &Command, data: &mut [u8], direction: DataDirection) -> KResult<()>;

    /// Queue facts a transport can establish during discovery. The conservative
    /// default preserves logical-sector alignment without inventing cache or
    /// discard guarantees. # C: O(1)
    fn queue_limits(&self, block_size: u32) -> KResult<QueueLimits> {
        QueueLimits::for_logical_block_size(block_size)
    }
}
