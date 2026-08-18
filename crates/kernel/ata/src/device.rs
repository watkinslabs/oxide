//! Driver-facing ATA command execution contract.

use block::KResult;

use crate::{IDENTIFY_BYTES, Taskfile, TaskfileResult};

/// One live ATA endpoint. The transport driver owns taskfile execution and
/// retained probe state; ATA owns translation and ABI presentation. # C: one command
pub trait Device: Send + Sync {
    /// Probe-time native ATA IDENTIFY DEVICE page. # C: O(1)
    fn identify_page(&self) -> Option<[u8; IDENTIFY_BYTES]>;

    /// Execute one validated ATA taskfile against this endpoint. # C: one command
    fn execute_taskfile(&self, taskfile: Taskfile, data: &mut [u8], timeout_ms: u32) -> KResult<TaskfileResult>;

    /// Largest contiguous raw ATA payload this controller can stage. # C: O(1)
    fn max_transfer_bytes(&self) -> usize;

    /// Whether this endpoint negotiated native command queueing. # C: O(1)
    fn ncq_enabled(&self) -> bool { false }
}
