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

use jbd2::{
    JournalSuperblock,
    JournalLogReader, ReplayError, ReplayStats,
    replay,
    StagedBlock, LogCursor, build_descriptor_block, build_commit_block,
    escape_journal_payload,
};

use crate::inode::{self, Inode};
use crate::mount::{Mount, MountError, write_byte_range, read_byte_range_pub};
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
            Err(_) => return Ok(None),  // not a journal SB → skip
        };
        let stats = replay(&log, &*self.dev, &jsb)
            .map_err(|_| MountError::BlockIo)?;
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
    pub fn commit_metadata(&self, mut staged: Vec<StagedBlock>) -> Result<u32, MountError> {
        if staged.is_empty() { return Ok(0); }
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
            Err(_) => return self.apply_staged_to_target(&staged).map(|_| 0),
        };
        let bs = jsb.block_size as usize;
        let n = staged.len() as u32;
        if n + 2 >= jsb.maxlen { return Err(MountError::NoSpace); }
        let mut cursor = LogCursor::new(jsb.start, jsb.maxlen, jsb.sequence);
        // Reserve descriptor + N data + commit.
        let desc_at = cursor.reserve(1);
        let data_at_first = cursor.reserve(n);
        let commit_at = cursor.reserve(1);
        let seq = cursor.seq;
        // Write descriptor.
        let dbuf = build_descriptor_block(seq, &staged, bs);
        log.write_journal_block(desc_at, &dbuf)?;
        // Write each data block (escape if first 4 bytes are JBD2_MAGIC).
        for (i, s) in staged.iter_mut().enumerate() {
            let mut b = s.data.clone();
            if b.len() != bs { b.resize(bs, 0); }
            escape_journal_payload(&mut b);
            log.write_journal_block(data_at_first + i as u32, &b)?;
        }
        // Write commit.
        let cbuf = build_commit_block(seq, bs);
        log.write_journal_block(commit_at, &cbuf)?;
        // Now apply each staged block to its target.
        self.apply_staged_to_target(&staged)?;
        // Mark journal clean (s_start = 0, bump sequence).
        let mut sb_bytes = sb_bytes;
        sb_bytes[0x18..0x1C].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
        sb_bytes[0x1C..0x20].copy_from_slice(&0u32.to_be_bytes());
        log.write_journal_block(0, &sb_bytes)?;
        Ok(seq)
    }

    /// Write each staged block to its target LBA verbatim.
    fn apply_staged_to_target(&self, staged: &[StagedBlock]) -> Result<(), MountError> {
        let bs = self.sb.block_size as u64;
        for s in staged {
            write_byte_range(&*self.dev, s.target_lba * bs, &s.data)?;
        }
        Ok(())
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
        ext.sort_by_key(|&(lb, _, _)| lb);
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
        write_byte_range(&*self.mount.dev, lba * bs, data)
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
