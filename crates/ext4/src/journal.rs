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
