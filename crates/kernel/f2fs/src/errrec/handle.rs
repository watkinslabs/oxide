//! What a mount does when it finds something wrong.
//!
//! Two entry points and one decision between them. An ORDINARY error is
//! recorded and the mount carries on: the volume is inconsistent in one place
//! and everything else is still readable, so refusing to serve it would lose
//! far more than the fault did. A CRITICAL one stops checkpointing, and what
//! happens after that is the `errors=` option's to say.
//!
//! The decision is a pure function of four bits, deliberately, because the
//! costly mistakes here are all orderings: recording a stop reason on a medium
//! that cannot be written, panicking on the way down when the device is
//! already gone, or going read-only on a shutdown, which is how a freeze
//! deadlocks.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::opts::Errors;
use crate::volume::Volume;

use super::uapi::{Error, StopReason};

/// Everything the critical path reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Situation {
    pub reason: StopReason,
    /// What the mount line said to do about an inconsistency.
    pub errors: Errors,
    /// Whether the medium refuses writes, so nothing can be recorded at all.
    pub hw_ro: bool,
    /// Whether the mount is already read-only, and so already cannot write.
    pub mount_ro: bool,
    /// Whether the volume has already been shut down.
    pub already_shutdown: bool,
    /// Whether the machine is on its way down, which forces the read-only
    /// behaviour whatever the option said: the device may already be gone, and
    /// a panic then is a crash with no diagnosis rather than one with a cause.
    pub going_down: bool,
}

/// What the mount is to do about it.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Outcome {
    /// Count the reason and push both arrays to the medium.
    pub record: bool,
    /// Stop with the option's own message.
    pub halt: bool,
    /// Mark the volume shut down.
    pub shutdown: bool,
    /// Stop serving writes.
    pub go_readonly: bool,
}

/// Decide, from the situation alone.
/// # C: O(1)
pub fn decide(s: &Situation) -> Outcome {
    let shutdown = s.reason == StopReason::Shutdown;
    // Nowhere to put the record. Counting it in memory and never writing it
    // would leave the array claiming a stop that no later mount can see.
    let record = !s.hw_ro;
    let halt = s.errors == Errors::Panic && !shutdown && !s.going_down && !s.already_shutdown;
    // A shutdown must NOT go read-only. Read-only is reached by the remount
    // path, which a shutdown is already past; taking it here blocks on a
    // freeze that nothing will now thaw.
    let continue_fs = !shutdown && s.errors == Errors::Continue;
    let go_readonly = !(continue_fs || s.mount_ro || shutdown);
    Outcome { record, halt, shutdown, go_readonly }
}

impl<S: SectorSource> Volume<S> {
    /// Note an inconsistency, and carry on.
    ///
    /// Returns whether it was news — a caller reporting upwards wants to say
    /// something once, not once per block of a damaged file.
    /// # C: O(1), plus a superblock commit when the kind is new
    pub fn handle_error(&mut self, e: Error) -> bool {
        if !self.errrec.save_error(e) { return false; }
        // Best effort: an error found while the medium refuses writes is still
        // worth holding in memory, because a later remount that can write
        // pushes it through.
        let _ = self.record_errors();
        true
    }

    /// Note an inconsistency without attempting to write it. # C: O(1)
    pub fn save_error(&mut self, e: Error) -> bool { self.errrec.save_error(e) }

    /// Stop checkpointing, for the stated reason, and act on `errors=`.
    ///
    /// Returns the outcome so the layer above can act on the halves this layer
    /// cannot: stopping the machine, and remounting read-only.
    /// # C: O(1), plus a superblock commit
    pub fn stop_checkpoint(&mut self, reason: StopReason, going_down: bool) -> Outcome {
        let s = Situation {
            reason,
            errors: self.opts.errors,
            hw_ro: !self.source.writable(),
            mount_ro: !self.writable,
            already_shutdown: self.sbi.shutdown(),
            going_down,
        };
        let out = decide(&s);
        // The checkpoint flag goes up FIRST. Everything below can fail, and a
        // volume that stopped for a reason it could not record must still stop.
        self.cp.flags |= crate::flags::CP_ERROR_FLAG;
        if out.record {
            self.errrec.save_stop_reason(reason);
            let _ = self.record_errors();
        }
        if out.shutdown { self.sbi.set(crate::sbflags::bits::IS_SHUTDOWN); }
        if out.go_readonly { self.writable = false; }
        out
    }

    /// Push both arrays through to the medium.
    ///
    /// Written through the ordinary two-copy commit, which is what makes the
    /// record survive a crash during the write that recorded it: the copy this
    /// mount does not believe goes down first.
    /// # C: O(2 blocks)
    pub fn record_errors(&mut self) -> Result<(), Errno> {
        if !self.errrec.dirty() { return Ok(()); }
        self.errrec.into_super(self.sb_raw.bytes_mut());
        let mount_ro = !self.writable;
        crate::sbwrite::commit_super(&self.source, &mut self.sb_raw, false, mount_ro,
                                     &mut self.sbi)
    }

    /// The record as it stands. # C: O(1)
    pub fn error_record(&self) -> &super::ErrorRecord { &self.errrec }
}

#[cfg(test)]
#[path = "../tests/errrec/handle.rs"]
mod tests;
