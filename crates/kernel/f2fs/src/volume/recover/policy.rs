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
    pub fn recover_at_mount(&mut self) -> Result<Recovery, Errno> {
        if !self.opts.recovery {
            // Asked not to replay. A chain is then dropped — but only a mount
            // that cannot write may drop it, because a writable mount would go
            // on to checkpoint over the blocks and destroy the evidence.
            if !self.has_fsync_data()? { return Ok(Recovery::Clean); }
            if self.writable { return Err(Errno::Einval); }
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
}

#[cfg(test)]
#[path = "../../tests/recover/policy.rs"]
mod tests;
