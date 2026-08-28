//! JBD2 home-block checkpoint ownership.
//!
//! The commit owner makes the journal record durable and retains the staged
//! home blocks here. The periodic flusher owns copying them to filesystem
//! LBAs; an explicit durability caller waits for the same owner to finish.

extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use crate::jbd2::{JournalLogReader, StagedBlock};
use crate::mount::{Mount, MountError};

/// One committed transaction retained until all of its home blocks have been
/// written and the journal superblock can be advanced past it.
pub(crate) struct PendingCheckpoint {
    pub(crate) staged: Vec<StagedBlock>,
    pub(crate) seq: u32,
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
            if s.pending_checkpoints.is_empty() { return Ok(()); }
            core::mem::take(&mut s.pending_checkpoints)
        };
        let last_seq = pending.last().map(|p| p.seq).unwrap_or(0);
        let result = self.checkpoint_staged(&pending).and_then(|_| {
            let jinode = self.read_inode(self.sb.journal_inum)?;
            let log = super::ExtentLogReader::build(self, &jinode)?;
            let sb_bytes = log.read_journal_block(0).map_err(|_| MountError::BlockIo)?;
            let jsb = super::JournalSuperblock::parse(&sb_bytes)
                .map_err(super::map_journal_superblock_error)?;
            self.mark_journal_clean_seq(&log, &jsb, last_seq)
        });
        if result.is_err() {
            let mut state = self.state.lock();
            state.pending_checkpoints = pending;
        } else {
            {
                let mut state = self.state.lock();
                state.journal_cursor = None;
                state.journal_used = 0;
            }
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

    fn checkpoint_staged(&self, pending: &[PendingCheckpoint]) -> Result<(), MountError> {
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
        let staged = coalesce_checkpoint_blocks(&pending);
        self.apply_staged_to_target(&staged)?;
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"target-write", started_ns,
            pending.iter().map(|p| p.staged.len() as u64).sum());

        #[cfg(feature = "debug-fsync-latency")]
        let flush_started_ns = crate::fsync_latency::now_ns();
        // The clean marker is allowed to lag: if it is lost, recovery repeats
        // an idempotent metadata transaction. If it is observed as clean, the
        // preceding flush proves every target block reached stable storage.
        if self.behaviour().barrier {
            self.dev.flush().map_err(|_| MountError::BlockIo)?;
        }
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"target-flush", flush_started_ns,
            pending.iter().map(|p| p.staged.len() as u64).sum());
        Ok(())
    }
}

/// Keep only the newest home-image for each target block across committed
/// transactions. The journal retains transaction order for recovery, but the
/// checkpoint owner has the same single-buffer ownership Linux uses: once a
/// block is dirtied again, an older checkpoint copy must not be written home
/// separately. Sorting by target also lets the device writer coalesce adjacent
/// home blocks into larger requests.
fn coalesce_checkpoint_blocks(pending: &[PendingCheckpoint]) -> Vec<StagedBlock> {
    let mut latest = BTreeMap::new();
    for transaction in pending {
        for block in &transaction.staged {
            latest.insert(block.target_lba, block.clone());
        }
    }
    latest.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(target_lba: u64, byte: u8) -> StagedBlock {
        StagedBlock { target_lba, data: alloc::vec![byte; 4] }
    }

    #[test]
    fn checkpoint_keeps_newest_image_for_repeated_home_block() {
        let pending = [
            PendingCheckpoint { staged: alloc::vec![block(20, 1), block(22, 3)], seq: 1 },
            PendingCheckpoint { staged: alloc::vec![block(20, 2), block(21, 4)], seq: 2 },
        ];
        let staged = coalesce_checkpoint_blocks(&pending);
        assert_eq!(staged.iter().map(|b| b.target_lba).collect::<Vec<_>>(), [20, 21, 22]);
        assert_eq!(staged[0].data, alloc::vec![2; 4]);
        assert_eq!(staged[1].data, alloc::vec![4; 4]);
        assert_eq!(staged[2].data, alloc::vec![3; 4]);
    }

    #[test]
    fn checkpoint_empty_input_stays_empty() {
        assert!(coalesce_checkpoint_blocks(&[]).is_empty());
    }
}
