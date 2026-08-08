// JBD2 integration: open the journal inode (sb.journal_inum),
// build an in-memory map from journal-block-index → fs LBA via
// the journal inode's extent tree, run replay against the
// device, then mark the journal clean.
//
// The journal inode is a regular ext4 inode whose data extents
// are the journal device blocks. v1 supports inline (depth-0)
// extent trees; deeper trees would require external index nodes.

extern crate alloc;
use alloc::vec::Vec;

use crate::jbd2::{
    JournalSuperblock,
    JournalSuperblockError,
    JournalLogReader, ReplayError, ReplayStats,
    replay,
    StagedBlock, LogCursor, TransactionError,
    transaction_block_count_for, emit_transaction_for,
};

use crate::inode::{self, Inode};
use crate::mount::{Mount, MountError, read_byte_range_pub};
use crate::superblock::INCOMPAT_RECOVER;

impl Mount {
    /// Replay the on-disk journal if `INCOMPAT_RECOVER` is set
    /// + `sb.s_journal_inum != 0`. After replay, marks the
    /// journal clean (sets `s_start = 0` in the journal SB on
    /// disk). No-op for filesystems with no journal or a clean
    /// log. Returns replay stats.
    /// # C: O(journal_size / fs_block) I/O
    pub fn recover_journal(&self) -> Result<Option<ReplayStats>, MountError> {
        if (self.sb.feature_incompat & INCOMPAT_RECOVER) == 0 { return Ok(None); }
        if self.sb.journal_inum == 0 { return Ok(None); }
        let jinode = self.read_inode(self.sb.journal_inum)?;
        let log = ExtentLogReader::build(self, &jinode)?;
        let sb_bytes = log.read_journal_block(0).map_err(|_| MountError::BlockIo)?;
        let jsb = match JournalSuperblock::parse(&sb_bytes) {
            Ok(s) => s,
            Err(e) => return Err(map_journal_superblock_error(e)),
        };
        let stats = replay(&log, &*self.dev, &jsb).map_err(|error| match error {
            ReplayError::BadChecksum => MountError::BadChecksum,
            ReplayError::BlockIo | ReplayError::Corrupt => MountError::BlockIo,
        })?;
        if stats.txns_replayed > 0 {
            self.mark_journal_clean(&log, &jsb)?;
        }
        Ok(Some(stats))
    }

    /// Set `s_start = 0` (and bump sequence) in the journal SB
    /// to mark it clean.
    fn mark_journal_clean(&self, log: &ExtentLogReader, jsb: &JournalSuperblock)
        -> Result<(), MountError>
    {
        let mut sb_bytes = log.read_journal_block(0).map_err(|_| MountError::BlockIo)?;
        if sb_bytes.len() < 0x20 { return Ok(()); }
        sb_bytes[0x18..0x1C].copy_from_slice(&jsb.sequence.wrapping_add(1).to_be_bytes());
        sb_bytes[0x1C..0x20].copy_from_slice(&0u32.to_be_bytes());
        if !jsb.stamp_checksum(&mut sb_bytes) { return Err(MountError::BadChecksum); }
        log.write_journal_block(0, &sb_bytes)
    }

    /// Commit a transaction: write descriptor + N data blocks +
    /// commit to the journal, then write the same data to its
    /// target LBAs. Returns the journal sequence used. Bumps the
    /// journal SB's `s_sequence` + `s_start` on success.
    ///
    /// Caller staged the metadata writes by reading-modifying-
    /// writing fs blocks and calling this before any direct
    /// `write_byte_range` to those targets. Failure modes:
    /// - `NoSpace` if the staged set exceeds journal capacity
    /// - `BlockIo` propagated from device errors
    /// # C: O(N staged) journal I/O + N target I/O
    pub fn commit_metadata(&self, staged: Vec<StagedBlock>) -> Result<u32, MountError> {
        if staged.is_empty() { return Ok(0); }
        #[cfg(feature = "debug-fsync-latency")]
        let staged_blocks = staged.len() as u64;
        if (self.sb.feature_incompat & crate::superblock::INCOMPAT_RECOVER) == 0
            && self.sb.journal_inum == 0
        {
            // No journal — fall back to direct writes.
            return self.apply_staged_to_target(&staged).map(|_| 0);
        }
        let jinode = match self.read_inode(self.sb.journal_inum) {
            Ok(i)  => i,
            Err(_) => return self.apply_staged_to_target(&staged).map(|_| 0),
        };
        let log = ExtentLogReader::build(self, &jinode)?;
        let sb_bytes = log.read_journal_block(0).map_err(|_| MountError::BlockIo)?;
        let jsb = match JournalSuperblock::parse(&sb_bytes) {
            Ok(s) => s,
            Err(e) => return Err(map_journal_superblock_error(e)),
        };
        let bs = jsb.block_size as usize;
        let bit64 = jsb.feature_incompat & crate::jbd2::superblock::JBD2_INCOMPAT_64BIT != 0;
        let checksum_mode = jsb.checksum_mode();
        let transaction_blocks = transaction_block_count_for(staged.len(), bs, bit64, checksum_mode)
            .map_err(|_| MountError::NoSpace)?;
        let mut cursor = LogCursor::new(jsb.start, jsb.first, jsb.maxlen, jsb.sequence);
        if transaction_blocks as u32 > cursor.usable() { return Err(MountError::NoSpace); }
        let desc_at = cursor.head;
        let seq = cursor.seq;
        #[cfg(feature = "debug-fsync-latency")]
        let journal_started_ns = crate::fsync_latency::now_ns();
        emit_transaction_for(seq, &staged, bs, bit64, &jsb.uuid, checksum_mode, |block| {
            let at = cursor.reserve(1);
            log.write_journal_block(at, block)
        }).map_err(|e| match e {
            TransactionError::Emit(crate::jbd2::EmitError::BlockNumber) => MountError::BadBlock,
            TransactionError::Emit(_) => MountError::NoSpace,
            TransactionError::Write(e) => e,
        })?;
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"journal-body", journal_started_ns, staged_blocks);
        // WAL barrier (jbd2 write-ahead, ext4fix §6.1): make the journal body
        // durable, THEN durably record s_start=desc_at + s_sequence=seq in the
        // journal SB, THEN (and only then) write the targets. Previously s_start
        // stayed 0 ("nothing to recover") for the whole window, so a crash after
        // the commit block but before the target writes finished lost the txn and
        // left the fs half-updated. Now such a crash replays [desc_at..commit].
        let mut sb_bytes = sb_bytes;
        #[cfg(feature = "debug-fsync-latency")]
        let flush_started_ns = crate::fsync_latency::now_ns();
        // WAL barrier #1. A failed flush means the journal body may NOT be on
        // stable media, so publishing `s_start` next would point recovery at a
        // transaction that might not exist. Discarding this error (the old
        // `let _ =`) made the write-ahead guarantee unverifiable even in
        // principle. Linux checks the flush's return value and propagates
        // any error from the journal commit path.
        self.dev.flush().map_err(|_| MountError::BlockIo)?;
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"journal-flush", flush_started_ns, staged_blocks);
        sb_bytes[0x18..0x1C].copy_from_slice(&seq.to_be_bytes());      // s_sequence = seq
        sb_bytes[0x1C..0x20].copy_from_slice(&desc_at.to_be_bytes());  // s_start = desc_at
        if !jsb.stamp_checksum(&mut sb_bytes) { return Err(MountError::BadChecksum); }
        log.write_journal_block(0, &sb_bytes)?;
        #[cfg(feature = "debug-fsync-latency")]
        let publish_started_ns = crate::fsync_latency::now_ns();
        // WAL barrier #2: "recover from desc_at" must be durable BEFORE any
        // target write, or a crash mid-checkpoint leaves the fs half-updated
        // with no record of the transaction to replay.
        self.dev.flush().map_err(|_| MountError::BlockIo)?;
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"journal-publish", publish_started_ns, staged_blocks);
        // Journal now leads the fs; apply staged blocks to their targets.
        #[cfg(feature = "debug-fsync-latency")]
        let target_started_ns = crate::fsync_latency::now_ns();
        self.apply_staged_to_target(&staged)?;
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"target-write", target_started_ns, staged_blocks);
        #[cfg(feature = "debug-fsync-latency")]
        let target_flush_started_ns = crate::fsync_latency::now_ns();
        // WAL barrier #3: the targets must be durable before the journal is
        // marked clean below, or recovery would skip a transaction whose
        // target writes are still in the device cache.
        self.dev.flush().map_err(|_| MountError::BlockIo)?;
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"target-flush", target_flush_started_ns, staged_blocks);
        // Checkpoint complete: mark the journal clean (s_start = 0, bump sequence).
        sb_bytes[0x18..0x1C].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
        sb_bytes[0x1C..0x20].copy_from_slice(&0u32.to_be_bytes());
        if !jsb.stamp_checksum(&mut sb_bytes) { return Err(MountError::BadChecksum); }
        log.write_journal_block(0, &sb_bytes)?;
        Ok(seq)
    }

    /// Write each staged block to its target LBA verbatim.
    fn apply_staged_to_target(&self, staged: &[StagedBlock]) -> Result<(), MountError> {
        let bs = self.sb.block_size as u64;
        for s in staged {
            // Checkpoint writes belong to the journal, not to whoever happened
            // to dirty the block, so they carry the journal's priority too.
            self.write_journal_byte_range(s.target_lba * bs, &s.data)?;
        }
        Ok(())
    }
}

fn map_journal_superblock_error(error: JournalSuperblockError) -> MountError {
    match error {
        JournalSuperblockError::BadChecksum => MountError::BadChecksum,
        JournalSuperblockError::BadFeatures | JournalSuperblockError::BadChecksumType => {
            MountError::UnsupportedFeature
        }
        JournalSuperblockError::Short
        | JournalSuperblockError::BadMagic
        | JournalSuperblockError::BadType => MountError::BlockIo,
    }
}

/// Maps journal-block index → physical fs LBA via the journal
/// inode's extent tree. Holds the parsed extents in a Vec for
/// O(N_extents) lookup per read.
pub struct ExtentLogReader<'m> {
    mount: &'m Mount,
    /// (logical_block, physical_lba, len) triples, sorted by
    /// logical_block.
    extents: Vec<(u32, u64, u32)>,
}

impl<'m> ExtentLogReader<'m> {
    fn build(mount: &'m Mount, jinode: &Inode) -> Result<Self, MountError> {
        let hdr = inode::parse_extent_header(&jinode.i_block)?;
        if hdr.depth != 0 { return Err(MountError::DepthUnsupported); }
        let mut ext = Vec::new();
        for i in 0..hdr.entries {
            if let Some(e) = inode::parse_inline_extent(&jinode.i_block, &hdr, i) {
                ext.push((e.block, e.start_lba(), e.len as u32));
            }
        }
        ext.sort_unstable_by_key(|&(lb, _, _)| lb);
        Ok(Self { mount, extents: ext })
    }

    fn map(&self, jblk: u32) -> Option<u64> {
        for &(lb, lba, len) in &self.extents {
            if jblk >= lb && jblk < lb + len {
                return Some(lba + (jblk - lb) as u64);
            }
        }
        None
    }

    fn write_journal_block(&self, jblk: u32, data: &[u8]) -> Result<(), MountError> {
        let lba = self.map(jblk).ok_or(MountError::NotFound)?;
        let bs = self.mount.sb.block_size as u64;
        // Journal traffic carries the mount's `journal_ioprio=`: it is the only
        // way the option reaches the queue that orders these writes against
        // everything else the device has in flight.
        self.mount.write_journal_byte_range(lba * bs, data)
    }
}

impl<'m> JournalLogReader for ExtentLogReader<'m> {
    fn read_journal_block(&self, jblk: u32) -> Result<Vec<u8>, ReplayError> {
        let lba = self.map(jblk).ok_or(ReplayError::BlockIo)?;
        let bs = self.mount.sb.block_size as u64;
        read_byte_range_pub(&*self.mount.dev, lba * bs, self.mount.sb.block_size as usize)
            .map_err(|_| ReplayError::BlockIo)
    }
}
