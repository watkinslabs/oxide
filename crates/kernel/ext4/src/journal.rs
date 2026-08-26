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
use crate::jbd2::checksum::ChecksumMode;

use crate::inode::{self, Inode};
use crate::mount::{Mount, MountError, read_byte_range_pub};
use crate::superblock::INCOMPAT_RECOVER;

impl Mount {
    const TARGET_WRITE_CLUSTER_BYTES: usize = 128 * 1024;

    /// Apply an explicit ext4 journal checksum mount option to the clean JBD2
    /// superblock. Replay is intentionally performed before this operation:
    /// the existing feature words are the authority for reading an old log.
    /// # C: O(1) journal-superblock I/O
    pub fn configure_journal_checksum(&self) -> Result<(), MountError> {
        let Some(enabled) = self.opts().behaviour.journal_checksum else { return Ok(()); };
        if self.sb.journal_inum == 0 { return Ok(()); }
        let jinode = self.read_inode(self.sb.journal_inum)?;
        let log = ExtentLogReader::build(self, &jinode)?;
        let old = log.read_journal_block(0).map_err(|_| MountError::BlockIo)?;
        let mut jsb = JournalSuperblock::parse(&old).map_err(map_journal_superblock_error)?;
        if jsb.needs_recovery() { return Err(MountError::UnsupportedFeature); }
        let desired = if enabled {
            if self.sb.has_metadata_csum() { ChecksumMode::V3 } else { ChecksumMode::V1 }
        } else { ChecksumMode::None };
        if jsb.checksum_mode() == desired { return Ok(()); }
        // JBD2's v1 superblock has no feature words. Linux only changes the
        // checksum feature set on the v2 superblock format; refusing here is
        // safer than writing bytes that replay will never read.
        if jsb.block_type != 4 { return Err(MountError::UnsupportedFeature); }
        jsb.set_checksum_mode(desired);
        let mut bytes = old;
        bytes[0x24..0x28].copy_from_slice(&jsb.feature_compat.to_be_bytes());
        bytes[0x28..0x2C].copy_from_slice(&jsb.feature_incompat.to_be_bytes());
        bytes[0x50] = jsb.checksum_type;
        if !jsb.stamp_checksum(&mut bytes) { return Err(MountError::BadChecksum); }
        log.write_journal_block(0, &bytes)?;
        self.dev.flush().map_err(|_| MountError::BlockIo)
    }

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
        let mut sb_bytes = log.read_journal_block(0).map_err(|_| MountError::BlockIo)?;
        let mut jsb = match JournalSuperblock::parse(&sb_bytes) {
            Ok(s) => s,
            Err(e) => return Err(map_journal_superblock_error(e)),
        };
        let bs = jsb.block_size as usize;
        let bit64 = jsb.feature_incompat & crate::jbd2::superblock::JBD2_INCOMPAT_64BIT != 0;
        let checksum_mode = self.opts().behaviour.journal_checksum.map(|enabled| {
            if enabled {
                if self.sb.has_metadata_csum() { ChecksumMode::V3 } else { ChecksumMode::V1 }
            } else { ChecksumMode::None }
        }).unwrap_or_else(|| jsb.checksum_mode());
        // A remount may have changed an explicit checksum option. The mount
        // path applies it eagerly; this branch keeps the same invariant for a
        // live remount before the first subsequent transaction.
        if jsb.checksum_mode() != checksum_mode {
            if jsb.needs_recovery() { return Err(MountError::UnsupportedFeature); }
            if jsb.block_type != 4 { return Err(MountError::UnsupportedFeature); }
            jsb.set_checksum_mode(checksum_mode);
            sb_bytes[0x24..0x28].copy_from_slice(&jsb.feature_compat.to_be_bytes());
            sb_bytes[0x28..0x2C].copy_from_slice(&jsb.feature_incompat.to_be_bytes());
            sb_bytes[0x50] = jsb.checksum_type;
            if !jsb.stamp_checksum(&mut sb_bytes) { return Err(MountError::BadChecksum); }
            log.write_journal_block(0, &sb_bytes)?;
            self.dev.flush().map_err(|_| MountError::BlockIo)?;
        }
        let transaction_blocks = transaction_block_count_for(staged.len(), bs, bit64, checksum_mode)
            .map_err(|_| MountError::NoSpace)?;
        let mut cursor = LogCursor::new(jsb.start, jsb.first, jsb.maxlen, jsb.sequence);
        if transaction_blocks as u32 > cursor.usable() { return Err(MountError::NoSpace); }
        let desc_at = cursor.head;
        let seq = cursor.seq;
        #[cfg(feature = "debug-fsync-latency")]
        let journal_started_ns = crate::fsync_latency::now_ns();
        let mut body = JournalBodyWriter::new(&log, bs);
        emit_transaction_for(seq, &staged, bs, bit64, &jsb.uuid, checksum_mode, |block| {
            let at = cursor.reserve(1);
            body.push(at, block)
        }).map_err(|e| match e {
            TransactionError::Emit(crate::jbd2::EmitError::BlockNumber) => MountError::BadBlock,
            TransactionError::Emit(_) => MountError::NoSpace,
            TransactionError::Write(e) => e,
        })?;
        // The whole body reaches the device before the barrier below, exactly
        // as it did when each block was its own request.
        body.flush()?;
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"journal-body", journal_started_ns, staged_blocks);
        // WAL barrier (jbd2 write-ahead, ext4fix §6.1): make the journal body
        // durable, THEN durably record s_start=desc_at + s_sequence=seq in the
        // journal SB, THEN (and only then) write the targets. Previously s_start
        // stayed 0 ("nothing to recover") for the whole window, so a crash after
        // the commit block but before the target writes finished lost the txn and
        // left the fs half-updated. Now such a crash replays [desc_at..commit].
        let mut sb_bytes = sb_bytes;
        sb_bytes[0x18..0x1C].copy_from_slice(&seq.to_be_bytes());      // s_sequence = seq
        sb_bytes[0x1C..0x20].copy_from_slice(&desc_at.to_be_bytes());  // s_start = desc_at
        if !jsb.stamp_checksum(&mut sb_bytes) { return Err(MountError::BadChecksum); }
        #[cfg(feature = "debug-fsync-latency")]
        let publish_started_ns = crate::fsync_latency::now_ns();
        // The journal superblock publication is the commit record's
        // durability point. Its preflush makes the already-submitted body
        // durable first; FUA (or the block layer's postflush fallback) makes
        // this publication durable before any checkpoint target write.
        log.write_journal_block_durable(0, &sb_bytes)?;
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
        #[cfg(feature = "debug-faultcost")]
        let _src = crate::WriteSource::checkpoint();
        let bs = self.sb.block_size as u64;
        let block_bytes = bs as usize;
        for (start_lba, run) in coalesce_target_writes(
            staged, block_bytes, Self::TARGET_WRITE_CLUSTER_BYTES)?
        {
            // Checkpoint writes belong to the journal, not to whoever
            // happened to dirty the block, so they carry the journal's
            // priority too. Coalesce adjacent targets into one BIO-sized
            // request, as Linux writeback does.
            self.write_journal_byte_range(start_lba * bs, &run)?;
        }
        Ok(())
    }
}

fn coalesce_target_writes(
    staged: &[StagedBlock], block_bytes: usize, max_bytes: usize,
) -> Result<Vec<(u64, Vec<u8>)>, MountError> {
    if block_bytes == 0 || max_bytes < block_bytes { return Err(MountError::BlockIo); }
    let mut runs = Vec::new();
    let mut run_start = None;
    let mut next_lba = 0u64;
    let mut run = Vec::new();
    for s in staged {
        if s.data.len() != block_bytes { return Err(MountError::BlockIo); }
        let contiguous = run_start.is_some()
            && s.target_lba == next_lba
            && run.len().saturating_add(block_bytes) <= max_bytes;
        if !contiguous && !run.is_empty() {
            runs.push((run_start.unwrap(), core::mem::take(&mut run)));
        }
        if run_start.is_none() || !contiguous { run_start = Some(s.target_lba); }
        run.extend_from_slice(&s.data);
        next_lba = s.target_lba + 1;
    }
    if !run.is_empty() { runs.push((run_start.unwrap(), run)); }
    Ok(runs)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::coalesce_target_writes;
    use crate::jbd2::StagedBlock;

    fn block(lba: u64, value: u8) -> StagedBlock {
        StagedBlock { target_lba: lba, data: vec![value; 4] }
    }

    #[test]
    fn coalesces_adjacent_blocks_and_splits_gaps() {
        let staged = [block(10, 1), block(11, 2), block(13, 3)];
        let runs = coalesce_target_writes(&staged, 4, 8).unwrap();
        assert_eq!(runs, vec![(10, vec![1, 1, 1, 1, 2, 2, 2, 2]), (13, vec![3; 4])]);
    }

    #[test]
    fn splits_a_contiguous_run_at_the_bio_bound() {
        let staged = [block(20, 1), block(21, 2), block(22, 3)];
        let runs = coalesce_target_writes(&staged, 4, 8).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].0, 20);
        assert_eq!(runs[1].0, 22);
    }

    #[test]
    fn rejects_a_partial_staged_block() {
        let staged = [StagedBlock { target_lba: 1, data: vec![0; 3] }];
        assert_eq!(coalesce_target_writes(&staged, 4, 8), Err(crate::MountError::BlockIo));
    }
}

/// Accumulate journal-body blocks into contiguous device runs.
///
/// Every block of a transaction used to be its own `submit_sync`: a 512-block
/// transaction meant 512 serialised round-trips through the queue before the
/// commit barrier could even start. The reference submits the log as bios that
/// span many blocks, and a transaction's blocks are laid out sequentially in
/// the log, so they coalesce almost perfectly. The bytes, their order and the
/// barrier that follows them are unchanged; only the number of requests drops.
struct JournalBodyWriter<'a, 'm> {
    log:       &'a ExtentLogReader<'m>,
    block_len: usize,
    /// Device byte offset the buffered run starts at.
    run_at:    Option<u64>,
    /// Device byte offset the next block must land at to extend the run.
    next_at:   u64,
    run:       Vec<u8>,
}

impl<'a, 'm> JournalBodyWriter<'a, 'm> {
    fn new(log: &'a ExtentLogReader<'m>, block_len: usize) -> Self {
        Self { log, block_len, run_at: None, next_at: 0, run: Vec::new() }
    }

    /// Buffer one journal block, flushing first when it does not extend the
    /// current run or the run has reached the request cluster.
    /// # C: O(block) amortised, one device write per run
    fn push(&mut self, jblk: u32, data: &[u8]) -> Result<(), MountError> {
        if data.len() != self.block_len { return Err(MountError::BlockIo); }
        let bs = self.log.mount.sb.block_size as u64;
        let at = self.log.map(jblk).ok_or(MountError::NotFound)? * bs;
        let extends = self.run_at.is_some()
            && at == self.next_at
            && self.run.len().saturating_add(self.block_len) <= Mount::TARGET_WRITE_CLUSTER_BYTES;
        if !extends { self.flush()?; self.run_at = Some(at); }
        self.run.extend_from_slice(data);
        self.next_at = at + self.block_len as u64;
        Ok(())
    }

    /// Issue the buffered run, if any. # C: one device write
    fn flush(&mut self) -> Result<(), MountError> {
        let Some(at) = self.run_at.take() else { self.run.clear(); return Ok(()); };
        if self.run.is_empty() { return Ok(()); }
        #[cfg(feature = "debug-faultcost")]
        let _src = crate::WriteSource::journal();
        self.log.mount.write_journal_byte_range(at, &self.run)?;
        self.run.clear();
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

    fn write_journal_block_durable(&self, jblk: u32, data: &[u8]) -> Result<(), MountError> {
        let lba = self.map(jblk).ok_or(MountError::NotFound)?;
        let bs = self.mount.sb.block_size as u64;
        crate::mount::write_durable_block(
            &*self.mount.dev, lba * bs, data, self.mount.journal_request_ioprio(),
        )
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
