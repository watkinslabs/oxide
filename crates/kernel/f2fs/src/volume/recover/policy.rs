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

use crate::flags::CP_UMOUNT_FLAG;
use crate::volume::Volume;

use super::replay::Recovery;

impl<S: SectorSource> Volume<S> {
    /// Deal with whatever the last mount left behind.
    ///
    /// A volume the last mount unmounted costs nothing: the checkpoint states
    /// it, and nothing can have been written after the checkpoint that ended
    /// the mount. Anything else reads at least the log's next block.
    /// # C: O(chain length) blocks, none after a clean unmount
    pub fn recover_at_mount(&mut self) -> Result<Recovery, Errno> {
        // A volume the last mount closed cleanly has nothing past its
        // checkpoint by construction, and says so in the checkpoint itself.
        // Every other path below reads at least one block to find that out.
        if self.cp.has(CP_UMOUNT_FLAG) { return Ok(Recovery::Clean); }
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
