// JBD2 commit-emission: build descriptor + commit blocks for one
// transaction, plus a write-side cursor that tracks the next-free
// journal block. Replay (in `replay.rs`) is the recovery side;
// this is the steady-state-write side.
//
// One transaction:
//   N target writes, where each write is one fs-block-sized buffer
//   destined for an fs LBA → emit:
//     - one descriptor block listing all N target LBAs
//     - N data blocks holding the new contents (escape-handled)
//     - one commit block
// Caller is responsible for issuing these in order to the journal
// device, then issuing the same N data blocks to their original
// LBAs, then sync, then advancing the journal cursor's in-memory
// `start` so the journal SB on disk can be marked clean.

extern crate alloc;
use alloc::vec::Vec;

use crate::block_header::{BlockHeader, BlockType, JBD2_MAGIC};
use crate::descriptor::{TAG_FLAG_ESCAPE, TAG_FLAG_LAST, TAG_FLAG_SAME_UUID};

/// One staged metadata write awaiting commit.
#[derive(Clone, Debug)]
pub struct StagedBlock {
    /// Target fs LBA the data should ultimately land at.
    pub target_lba: u64,
    /// Block contents (length = journal block size).
    pub data:       Vec<u8>,
}

/// Build the on-disk descriptor block for one transaction.
/// `block_size` is the journal block size (= fs block size for
/// internal journals). Returns `block_size` bytes ready to write
/// to a journal block.
///
/// Layout: 12-byte header + N tags. We always emit `bit64=false`
/// + `SAME_UUID` on every tag (skipping the 16-byte UUID) for
/// minimum bytes; the last tag carries `LAST`.
/// # C: O(N tags)
pub fn build_descriptor_block(seq: u32, staged: &[StagedBlock], block_size: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; block_size];
    BlockHeader { block_type: BlockType::Descriptor, sequence: seq }.write_to(&mut buf);
    let mut off = 12;
    for (i, s) in staged.iter().enumerate() {
        if off + 8 > buf.len() { break; }
        let mut flags = TAG_FLAG_SAME_UUID;
        if i == staged.len() - 1 { flags |= TAG_FLAG_LAST; }
        // Escape if the first 4 bytes of the data block would
        // collide with JBD2_MAGIC (replay restores them).
        let escape = if s.data.len() >= 4 {
            u32::from_be_bytes([s.data[0], s.data[1], s.data[2], s.data[3]]) == JBD2_MAGIC
        } else { false };
        if escape { flags |= TAG_FLAG_ESCAPE; }
        buf[off    ..off+ 4].copy_from_slice(&(s.target_lba as u32).to_be_bytes());
        buf[off+ 4..off+ 8].copy_from_slice(&flags.to_be_bytes());
        off += 8;
    }
    buf
}

/// Build a commit block for transaction `seq`. v1 emits the
/// minimum: header + zero body. Real JBD2 commits include a
/// timestamp + checksum; v2-of-v1 will add those.
/// # C: O(1)
pub fn build_commit_block(seq: u32, block_size: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; block_size];
    BlockHeader { block_type: BlockType::Commit, sequence: seq }.write_to(&mut buf);
    buf
}

/// If a staged block's first 4 bytes match JBD2_MAGIC, replace
/// them with zeros before writing to the journal (escape rule).
/// Replay restores the magic when applying.
/// # C: O(1)
pub fn escape_journal_payload(data: &mut [u8]) {
    if data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == JBD2_MAGIC {
        data[0..4].copy_from_slice(&0u32.to_be_bytes());
    }
}

/// Write-side cursor over the journal log. Tracks the next-free
/// journal block to use; wraps at `maxlen`, never returns 0
/// (block 0 = SB).
#[derive(Copy, Clone, Debug)]
pub struct LogCursor {
    pub head:    u32,
    pub maxlen:  u32,
    pub seq:     u32,
}

impl LogCursor {
    /// # C: O(1)
    pub fn new(start: u32, maxlen: u32, seq: u32) -> Self {
        let head = if start == 0 { 1 } else { start };
        Self { head, maxlen, seq }
    }

    /// Reserve `n` journal-block slots; returns the first slot's
    /// index. Wraps past `maxlen`; never returns 0.
    /// # C: O(1)
    pub fn reserve(&mut self, n: u32) -> u32 {
        let first = self.head;
        let mut h = self.head as u64 + n as u64;
        let m = self.maxlen as u64;
        if m > 1 {
            while h >= m {
                h -= m - 1;
                if h == 0 { h = 1; }
            }
        }
        self.head = h as u32;
        first
    }

    /// Bump the transaction sequence number after a commit lands.
    /// # C: O(1)
    pub fn bump_seq(&mut self) { self.seq = self.seq.wrapping_add(1); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::DescriptorIter;

    fn s(target_lba: u64, byte: u8, bs: usize) -> StagedBlock {
        StagedBlock { target_lba, data: alloc::vec![byte; bs] }
    }

    #[test]
    fn descriptor_round_trips_through_iter() {
        let bs = 1024;
        let blocks = std::vec![s(7, 0xAA, bs), s(42, 0xBB, bs), s(100, 0xCC, bs)];
        let dbuf = build_descriptor_block(5, &blocks, bs);
        let header = BlockHeader::parse(&dbuf).unwrap();
        assert_eq!(header.block_type, BlockType::Descriptor);
        assert_eq!(header.sequence, 5);
        let tags: std::vec::Vec<_> = DescriptorIter::new(&dbuf[12..], false).collect();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].tag.blocknr, 7);
        assert_eq!(tags[2].tag.blocknr, 100);
        assert!((tags[2].tag.flags & TAG_FLAG_LAST) != 0);
    }

    #[test]
    fn descriptor_marks_escape_on_magic_collision() {
        let bs = 64;
        let mut data = alloc::vec![0u8; bs];
        data[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        let blocks = std::vec![StagedBlock { target_lba: 7, data }];
        let dbuf = build_descriptor_block(1, &blocks, 1024);
        let tags: std::vec::Vec<_> = DescriptorIter::new(&dbuf[12..], false).collect();
        assert!((tags[0].tag.flags & TAG_FLAG_ESCAPE) != 0,
                "first-4-byte magic collision triggers ESCAPE");
    }

    #[test]
    fn commit_block_parses() {
        let buf = build_commit_block(5, 1024);
        let h = BlockHeader::parse(&buf).unwrap();
        assert_eq!(h.block_type, BlockType::Commit);
        assert_eq!(h.sequence, 5);
    }

    #[test]
    fn log_cursor_reserves_and_wraps() {
        let mut c = LogCursor::new(1, 8, 1);
        assert_eq!(c.reserve(3), 1); assert_eq!(c.head, 4);
        assert_eq!(c.reserve(3), 4); assert_eq!(c.head, 7);
        // 7 + 3 = 10; maxlen 8; should wrap.
        let r = c.reserve(3);
        assert_eq!(r, 7);
        assert!(c.head < 8 && c.head != 0, "wrapped, never zero");
    }

    #[test]
    fn descriptor_then_data_then_commit_replays_through_replay() {
        // End-to-end: build descriptor + commit + data, hand them
        // to replay::replay against a memory-backed disk, observe
        // the target writes apply.
        use crate::replay::{replay, JournalLogReader, ReplayError};
        use sync::TaskList;
        use block::MemDisk;
        use alloc::sync::Arc;

        struct VecJournal(std::vec::Vec<std::vec::Vec<u8>>);
        impl JournalLogReader for VecJournal {
            fn read_journal_block(&self, jblk: u32) -> Result<std::vec::Vec<u8>, ReplayError> {
                self.0.get(jblk as usize).cloned().ok_or(ReplayError::BlockIo)
            }
        }
        let bs = 1024usize;
        let staged = std::vec![s(5, 0xDE, bs), s(11, 0xAD, bs)];
        let desc = build_descriptor_block(7, &staged, bs);
        let commit = build_commit_block(7, bs);
        let mut blocks: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
        blocks.push(alloc::vec![0u8; bs]);  // index 0 = sb pad
        blocks.push(desc);                   // 1 = descriptor
        for s in &staged { blocks.push(s.data.clone()); }
        blocks.push(commit);
        let j = VecJournal(blocks);
        let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 32);
        let sb = crate::JournalSuperblock {
            block_size: bs as u32, maxlen: 32, first: 1, sequence: 7, start: 1,
            feature_compat: 0, feature_incompat: 0, feature_ro: 0,
        };
        let stats = replay(&j, &*disk, &sb).unwrap();
        assert_eq!(stats.txns_replayed, 1);
        assert_eq!(stats.blocks_applied, 2);
    }
}
