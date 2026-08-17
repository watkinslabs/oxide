//! Requests for a checkpoint, and the one write that serves all of them.
//!
//! A checkpoint is the most expensive thing this filesystem does and it is
//! WHOLE: it persists everything the mount has changed, not one caller's share.
//! So N callers arriving at once do not need N checkpoints — one write makes all
//! of their promises true, and the only reason a build without this pays N is
//! that each caller does its own.
//!
//! The merge is therefore a queue and a generation. A caller enrols by raising
//! the queue and reading the generation, the thread takes the whole queue in one
//! go, writes ONE checkpoint, records the result and raises the generation; every
//! caller that was enrolled sees the generation move and returns that one result.
//! A caller arriving after the take is enrolled for the NEXT write, which is
//! required rather than merely tidy: its own changes may not have been in the
//! state the write that is already running captured.
//!
//! Two callers must never be merged and both are the reference's own exemptions:
//! a mount that was not asked to merge, and the task taking the filesystem down
//! — which cannot wait for a thread it is in the middle of stopping.
//!
//! Nothing here sleeps or spawns. The parking is in `run`, the pure decision is
//! in `crate::checkpoint::merge`, and what is here is the state both read.

use vfs::VfsError;

/// The scheduling class the merge thread writes its checkpoints under.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IoClass {
    /// Ahead of ordinary traffic: a checkpoint everybody is blocked on.
    RealTime,
    /// Alongside it.
    BestEffort,
}

/// How the thread is scheduled, as the control file states it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct IoPrio {
    pub class: IoClass,
    pub level: u8,
}

/// Levels a class has, which is what bounds the written value.
pub const IOPRIO_LEVELS: u8 = 8;

impl IoPrio {
    /// What the thread starts at, which is what the reference starts it at:
    /// best-effort, at the middle level, so a checkpoint neither starves
    /// ordinary traffic nor waits behind all of it.
    /// # C: O(1)
    pub const fn at_start() -> Self { Self { class: IoClass::BestEffort, level: 3 } }
}

/// Everything the merge queue holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CkptControl {
    /// Callers enrolled and not yet served.
    queued: u32,
    /// Writes this thread has made. A report of work done, so it only rises.
    issued: u64,
    /// Callers served in total, which is what makes the saving visible: the
    /// difference between this and `issued` is the checkpoints not written.
    total: u64,
    /// Raised once per served batch. A caller waits for it to MOVE rather than
    /// for a flag, so a batch that completes between its enrolment and its park
    /// cannot leave it waiting for a wake that has already happened.
    generation: u64,
    /// The result of the last batch, which every caller of that batch returns.
    last: Result<(), VfsError>,
    /// Set by a caller that wants the thread's sleep cut short.
    pub wake: bool,
    /// How the thread is scheduled.
    pub ioprio: IoPrio,
}

impl Default for CkptControl {
    fn default() -> Self { Self::new() }
}

impl CkptControl {
    /// # C: O(1)
    pub fn new() -> Self {
        Self { queued: 0, issued: 0, total: 0, generation: 0, last: Ok(()), wake: false,
               ioprio: IoPrio::at_start() }
    }

    /// Enrol one caller, answering the generation it must wait to pass.
    /// # C: O(1)
    pub fn enrol(&mut self) -> u64 {
        self.queued = self.queued.saturating_add(1);
        self.wake = true;
        self.generation
    }

    /// Take the whole queue, answering how many callers this write will serve.
    ///
    /// All of it, never a share: the write about to be made persists everything
    /// the mount has changed, so it serves every caller that is already
    /// enrolled and there is no reading under which one of them should wait for
    /// a second write.
    /// # C: O(1)
    pub fn take(&mut self) -> u32 {
        self.wake = false;
        core::mem::take(&mut self.queued)
    }

    /// Record what the write did, and release everybody it served.
    /// # C: O(1)
    pub fn served(&mut self, count: u32, outcome: Result<(), VfsError>) {
        self.last = outcome;
        self.issued = self.issued.saturating_add(1);
        self.total = self.total.saturating_add(u64::from(count));
        self.generation = self.generation.wrapping_add(1);
    }

    /// Callers enrolled and not yet served. # C: O(1)
    pub fn queued(&self) -> u32 { self.queued }

    /// Writes made. # C: O(1)
    pub fn issued(&self) -> u64 { self.issued }

    /// Callers served. # C: O(1)
    pub fn total(&self) -> u64 { self.total }

    /// The batch counter a caller waits to pass. # C: O(1)
    pub fn generation(&self) -> u64 { self.generation }

    /// The result of the last batch. # C: O(1)
    pub fn last(&self) -> Result<(), VfsError> { self.last }
}

#[cfg(test)]
#[path = "../tests/bg/ckpt.rs"]
mod tests;
