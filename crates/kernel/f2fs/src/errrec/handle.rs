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
    /// Note an inconsistency from a path that cannot write, reporting whether
    /// it was news.
    ///
    /// The entry point every detection site uses, because nearly all of them
    /// are reads: an inode whose checksum fails, a footer naming the wrong
    /// node, an address outside the main area. Recording is separated from
    /// pushing for that reason — a `&self` path can add to the record, and the
    /// next path that can write puts it on the medium.
    ///
    /// News, rather than every occurrence, is what a caller reports upwards: a
    /// damaged file yields one fault, not one per block.
    /// # C: O(1)
    pub fn note_error(&self, e: Error) -> bool {
        let mut r = self.errrec.get();
        let news = r.save_error(e);
        if news { self.errrec.set(r); }
        news
    }

    /// Note an inconsistency, and put it on the medium now.
    /// # C: O(1), plus a superblock commit when the kind is new
    pub fn handle_error(&mut self, e: Error) -> bool {
        if !self.note_error(e) { return false; }
        // Best effort: an error found while the medium refuses writes is still
        // worth holding in memory, because a later remount that can write
        // pushes it through.
        let _ = self.record_errors();
        true
    }

    /// Note an inconsistency without attempting to write it. # C: O(1)
    pub fn save_error(&mut self, e: Error) -> bool { self.note_error(e) }

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
            let mut r = self.errrec.get();
            r.save_stop_reason(reason);
            self.errrec.set(r);
            let _ = self.record_errors();
        }
        // Before the arms below, as the reference panics before it marks the
        // volume down or takes it read-only: those two are what a mount that
        // SURVIVES the error does, and this one was told not to survive it.
        // The demand goes to the layer that owns the machine (`vfs::fs_halt`);
        // a build with no halt path installed is told so and carries on down
        // the remaining arms, which is what the reference does when a halt is
        // suppressed.
        if out.halt { vfs::fs_halt(crate::mount::F2FS_NAME, reason.as_str()); }
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
        let mut r = self.errrec.get();
        if !r.dirty() { return Ok(()); }
        r.into_super(self.sb_raw.bytes_mut());
        self.errrec.set(r);
        let mount_ro = !self.writable;
        crate::sbwrite::commit_super(&self.source, &mut self.sb_raw, false, mount_ro,
                                     &mut self.sbi)
    }

    /// The record as it stands. # C: O(1)
    pub fn error_record(&self) -> super::ErrorRecord { self.errrec.get() }
}

#[cfg(test)]
#[path = "../tests/errrec/handle.rs"]
mod tests;

/// Proof that the two entry points above are REACHED by ordinary operations,
/// which is the half that was missing rather than the machinery.
#[cfg(test)]
#[path = "../tests/errrec/sites.rs"]
mod sites;
