//! JBD2 home-block checkpoint ownership.
//!
//! The commit owner makes the journal record durable and retains the staged
//! home blocks here. The periodic flusher owns copying them to filesystem
//! LBAs; an explicit durability caller waits for the same owner to finish.

extern crate alloc;

use alloc::vec::Vec;

use crate::jbd2::{JournalLogReader, StagedBlock};
use crate::mount::{Mount, MountError};

/// One committed transaction retained until all of its home blocks have been
/// written and the journal superblock can be advanced past it.
pub(crate) struct PendingCheckpoint {
    pub(crate) staged: Vec<StagedBlock>,
}

impl Mount {
    /// Complete the retained transaction while the caller owns the mount
    /// transaction gate. The pending value is restored on any I/O failure so
    /// a later checkpoint pass can retry it without falsely advancing the log
    /// tail.
    /// # C: O(N staged) target I/O + one barrier
    pub(crate) fn checkpoint_pending(&self) -> Result<(), MountError> {
        let pending = {
            let mut s = self.state.lock();
            s.pending_checkpoint.take()
        };
        let Some(pending) = pending else { return Ok(()); };
        let result = self.checkpoint_staged(&pending.staged);
        if result.is_err() {
            self.state.lock().pending_checkpoint = Some(pending);
        }
        result
    }

    /// Checkpoint from the periodic owner. It takes the same transaction gate
    /// as mutators, which orders an older home write before a newer transaction
    /// can modify the same filesystem block.
    /// # C: O(N staged) target I/O + one barrier
    pub(crate) fn checkpoint_pending_background(&self) -> Result<(), MountError> {
        self.txn_acquire();
        let result = self.checkpoint_pending();
        self.txn_release();
        result
    }

    /// Checkpoint an outstanding transaction for an explicit sync owner.
    /// # C: O(N staged) target I/O + one barrier
    pub(crate) fn checkpoint_pending_sync(&self) -> Result<(), MountError> {
        self.txn_acquire();
        let result = self.checkpoint_pending();
        self.txn_release();
        result
    }

    fn checkpoint_staged(&self, staged: &[StagedBlock]) -> Result<(), MountError> {
        let jinode = self.read_inode(self.sb.journal_inum)?;
        let log = super::ExtentLogReader::build(self, &jinode)?;
        let sb_bytes = log.read_journal_block(0).map_err(|_| MountError::BlockIo)?;
        let jsb = super::JournalSuperblock::parse(&sb_bytes)
            .map_err(super::map_journal_superblock_error)?;
        // The publication request may have completed at the transport while
        // power failed before its bytes reached media. In that case the
        // surviving superblock is still clean: there is no committed log
        // record for this owner to checkpoint, so discard the in-memory
        // pending value and let the interrupted operation's caller observe
        // the power-cut outcome through the device contract.
        if !jsb.needs_recovery() { return Ok(()); }

        #[cfg(feature = "debug-fsync-latency")]
        let started_ns = crate::fsync_latency::now_ns();
        self.apply_staged_to_target(staged)?;
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"target-write", started_ns, staged.len() as u64);

        #[cfg(feature = "debug-fsync-latency")]
        let flush_started_ns = crate::fsync_latency::now_ns();
        // The clean marker is allowed to lag: if it is lost, recovery repeats
        // an idempotent metadata transaction. If it is observed as clean, the
        // preceding flush proves every target block reached stable storage.
        if self.behaviour().barrier {
            self.dev.flush().map_err(|_| MountError::BlockIo)?;
        }
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"target-flush", flush_started_ns, staged.len() as u64);
        self.mark_journal_clean(&log, &jsb)
    }
}
