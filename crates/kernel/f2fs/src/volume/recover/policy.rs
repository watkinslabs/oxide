//! What a mount does about a chain it finds, given what it is allowed to do.
//!
//! Three answers, and the wrong one in either direction is a data loss. A
//! mount that replays when it was told not to overwrites state the operator
//! asked to keep untouched. A mount that silently skips a chain it could have
//! replayed hands back a filesystem missing writes an `fsync` promised — and
//! the next clean unmount retires the chain's blocks, so the loss becomes
//! permanent without anything ever reporting it.

use syscall::errno::Errno;

use sectors::SectorSource;


use crate::volume::Volume;

use super::replay::Recovery;

impl<S: SectorSource> Volume<S> {
    /// Deal with whatever the last mount left behind.
    ///
    /// The clean-unmount mark is NOT consulted, and reading it as "nothing
    /// follows this checkpoint" loses data. It states how the checkpoint on
    /// the medium was written, not what has happened since — and a mount that
    /// writes a chain and never checkpoints leaves that mark exactly as it
    /// found it. Skip on it and the next mount walks past everything an
    /// `fsync` promised in between: a file created, written, made durable and
    /// then lost to a crash simply is not there. What decides the question is
    /// the walk itself, and after a genuine clean unmount it costs one block —
    /// the log's next block belongs to an older generation and stops it.
    /// # C: O(chain length) blocks, one after a clean unmount
    #[inline(never)]
    pub fn recover_at_mount(&mut self) -> Result<Recovery, Errno> {
        if !self.opts.recovery {
            // Asked not to replay, by either of the two options that say so.
            // The chain is DROPPED, and on a writable mount the next
            // checkpoint writes over its blocks — which is what the option is
            // for, not an accident of it.
            //
            // The two are not the same request and are not conflated here.
            // `disable_roll_forward` is legal on a writable mount and this is
            // its whole effect; `norecovery` additionally demands a mount that
            // cannot write, and that demand is settled by the option pass
            // every mount runs, before anything reads a chain. Repeating it
            // here would be a second answer to a question already answered —
            // and a wrong one, since it would refuse the other option too.
            if !self.has_fsync_data()? { return Ok(Recovery::Clean); }
            return Ok(Recovery::Skipped);
        }
        if !self.writable {
            if !self.has_fsync_data()? { return Ok(Recovery::Clean); }
            // The medium itself refuses writes, so the chain can never be
            // replayed and reporting the volume as mountable would report a
            // filesystem missing writes that were promised.
            if !self.source.writable() { return Err(Errno::Erofs); }
            return Ok(Recovery::Skipped);
        }
        self.recover()
    }

    /// Lift this mount's read-only for the length of a repair, if it owes one.
    ///
    /// Returns nothing: what was done is recorded in the status word, and the
    /// end of the window reads it back from there. A second copy of that
    /// answer held by the caller could disagree with the word every reporting
    /// surface publishes.
    /// # C: O(1)
    #[inline(never)]
    pub(crate) fn begin_repair_write(&mut self) {
        let need = super::rw::need_recovery(super::rw::Facts {
            orphans_present: self.cp.has(crate::flags::CP_ORPHAN_PRESENT_FLAG),
            replays: self.opts.recovery,
            clean_umount: self.cp.has(crate::flags::CP_UMOUNT_FLAG),
        });
        if !super::rw::lift_read_only(need, self.source.writable(), self.writable) { return; }
        self.writable = true;
        self.sbi.set_transiently_writable(true);
    }

    /// Raise the in-progress condition for the length of a replay.
    ///
    /// Everything that reads it is asking "is this volume's tail still
    /// unresolved": the cleaner, which must not move blocks a chain still names,
    /// the allocators that keep a reserve back, and the status word a tool
    /// reads. # C: O(1)
    pub(crate) fn begin_recovery(&mut self) { self.recovering = true; }

    /// Lower it — which ONLY a pass that succeeded may do.
    ///
    /// A failed replay leaves the tail unresolved, so the condition stays
    /// raised. Lowered anyway, the cleaner is told it may start moving live
    /// blocks the chain still names, and the status word reports a volume that
    /// came up clean. Raised is the recoverable direction: it costs a reserve
    /// and a stalled cleaner, where lowering it costs the data.
    /// # C: O(1)
    pub(crate) fn finish_recovery(&mut self, ok: bool) { if ok { self.recovering = false; } }

    /// Whether this mount is still part way through a replay. # C: O(1)
    pub fn is_recovering(&self) -> bool { self.recovering }

    /// Put the read-only back, if this mount lifted it. # C: O(1)
    pub(crate) fn end_repair_write(&mut self) {
        if !self.sbi.transiently_writable() { return; }
        self.sbi.set_transiently_writable(false);
        self.writable = false;
    }
}

#[cfg(test)]
#[path = "../../tests/recover/policy.rs"]
mod tests;
