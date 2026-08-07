// JBD2 commit-emission: build the descriptor/data groups + commit block for
// one transaction, plus a write-side cursor over the journal ring. Replay (in
// `replay.rs`) is the recovery side; this is the steady-state-write side.
//
// One transaction:
//   N target writes, where each write is one fs-block-sized buffer
//   destined for an fs LBA → emit:
//     - descriptor listing group 1, then group 1 data
//     - descriptor listing group 2, then group 2 data, as needed
//     - one commit block
// Caller is responsible for issuing these in order to the journal
// device, then issuing the same N data blocks to their original
// LBAs, then sync, then advancing the journal cursor's in-memory
// `start` so the journal SB on disk can be marked clean.

extern crate alloc;
use alloc::vec::Vec;

use super::block_header::{BlockHeader, BlockType, JBD2_MAGIC};
use super::descriptor::{TAG_FLAG_ESCAPE, TAG_FLAG_LAST, TAG_FLAG_SAME_UUID};

const HEADER_BYTES: usize = 12;
const TAG32_BYTES: usize = 8;
const TAG64_BYTES: usize = 12;
const UUID_BYTES: usize = 16;

/// One staged metadata write awaiting commit.
#[derive(Clone, Debug)]
pub struct StagedBlock {
    /// Target fs LBA the data should ultimately land at.
    pub target_lba: u64,
    /// Block contents (length = journal block size).
    pub data:       Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EmitError {
    Empty,
    BlockSize,
    BlockNumber,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TransactionError<E> {
    Emit(EmitError),
    Write(E),
}

/// Maximum unchecksummed tags one descriptor can encode. Every descriptor's
/// first tag carries the journal UUID; later tags set `SAME_UUID`.
/// # C: O(1)
pub fn descriptor_capacity(block_size: usize, bit64: bool) -> usize {
    let tag = if bit64 { TAG64_BYTES } else { TAG32_BYTES };
    block_size.saturating_sub(HEADER_BYTES + UUID_BYTES) / tag
}

/// Build the on-disk descriptor block for one transaction.
/// `block_size` is the journal block size (= fs block size for
/// internal journals). Returns `block_size` bytes ready to write
/// to a journal block.
///
/// Layout: 12-byte header + N tags. The first tag carries `uuid`; following
/// tags carry `SAME_UUID`. `LAST` closes this descriptor, not the transaction.
/// # C: O(N tags)
pub fn build_descriptor_block(
    seq: u32,
    staged: &[StagedBlock],
    block_size: usize,
    bit64: bool,
    uuid: &[u8; UUID_BYTES],
) -> Result<Vec<u8>, EmitError> {
    let cap = descriptor_capacity(block_size, bit64);
    if staged.is_empty() { return Err(EmitError::Empty); }
    if cap == 0 || staged.len() > cap { return Err(EmitError::BlockSize); }
    let mut buf = alloc::vec![0u8; block_size];
    BlockHeader { block_type: BlockType::Descriptor, sequence: seq }.write_to(&mut buf);
    let tag_bytes = if bit64 { TAG64_BYTES } else { TAG32_BYTES };
    let mut off = HEADER_BYTES;
    for (i, s) in staged.iter().enumerate() {
        if !bit64 && s.target_lba > u32::MAX as u64 { return Err(EmitError::BlockNumber); }
        let mut flags = if i == 0 { 0 } else { TAG_FLAG_SAME_UUID };
        if i == staged.len() - 1 { flags |= TAG_FLAG_LAST; }
        // Escape if the first 4 bytes of the data block would
        // collide with JBD2_MAGIC (replay restores them).
        let escape = if s.data.len() >= 4 {
            u32::from_be_bytes([s.data[0], s.data[1], s.data[2], s.data[3]]) == JBD2_MAGIC
        } else { false };
        if escape { flags |= TAG_FLAG_ESCAPE; }
        buf[off    ..off+ 4].copy_from_slice(&(s.target_lba as u32).to_be_bytes());
        buf[off+ 6..off+ 8].copy_from_slice(&(flags as u16).to_be_bytes());
        if bit64 {
            buf[off+ 8..off+12].copy_from_slice(&((s.target_lba >> 32) as u32).to_be_bytes());
        }
        off += tag_bytes;
        if i == 0 {
            buf[off..off + UUID_BYTES].copy_from_slice(uuid);
            off += UUID_BYTES;
        }
    }
    Ok(buf)
}

/// Journal slots occupied by one transaction: every staged payload, one
/// descriptor per capacity-sized group, then one commit block.
/// # C: O(1)
pub fn transaction_block_count(
    staged_len: usize,
    block_size: usize,
    bit64: bool,
) -> Result<usize, EmitError> {
    if staged_len == 0 { return Err(EmitError::Empty); }
    let cap = descriptor_capacity(block_size, bit64);
    if cap == 0 { return Err(EmitError::BlockSize); }
    Ok(staged_len + staged_len.div_ceil(cap) + 1)
}

/// Stream one complete transaction in journal order. Only the current
/// descriptor or payload is allocated, matching the write-side grouping rather
/// than cloning the whole transaction into a second in-memory batch.
/// # C: O(N staged blocks)
pub fn emit_transaction<E, F>(
    seq: u32,
    staged: &[StagedBlock],
    block_size: usize,
    bit64: bool,
    uuid: &[u8; UUID_BYTES],
    mut write: F,
) -> Result<(), TransactionError<E>>
where
    F: FnMut(&[u8]) -> Result<(), E>,
{
    transaction_block_count(staged.len(), block_size, bit64)
        .map_err(TransactionError::Emit)?;
    let cap = descriptor_capacity(block_size, bit64);
    for group in staged.chunks(cap) {
        let descriptor = build_descriptor_block(seq, group, block_size, bit64, uuid)
            .map_err(TransactionError::Emit)?;
        write(&descriptor).map_err(TransactionError::Write)?;
        for s in group {
            let mut data = s.data.clone();
            if data.len() != block_size { data.resize(block_size, 0); }
            escape_journal_payload(&mut data);
            write(&data).map_err(TransactionError::Write)?;
        }
    }
    let commit = build_commit_block(seq, block_size);
    write(&commit).map_err(TransactionError::Write)
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
    pub first:   u32,
    pub maxlen:  u32,
    pub seq:     u32,
}

impl LogCursor {
    /// # C: O(1)
    pub fn new(start: u32, first: u32, maxlen: u32, seq: u32) -> Self {
        let first = core::cmp::max(first, 1);
        let head = if start < first || start >= maxlen { first } else { start };
        Self { head, first, maxlen, seq }
    }

    /// Reserve `n` journal-block slots; returns the first slot's
    /// index. Wraps past `maxlen`; never returns 0.
    /// # C: O(1)
    pub fn reserve(&mut self, n: u32) -> u32 {
        let first = self.head;
        let range = self.maxlen.saturating_sub(self.first) as u64;
        if range != 0 {
            let off = (self.head - self.first) as u64;
            self.head = self.first + ((off + n as u64) % range) as u32;
        }
        first
    }

    /// Number of usable log slots, excluding the superblock/reserved prefix.
    /// # C: O(1)
    pub fn usable(&self) -> u32 { self.maxlen.saturating_sub(self.first) }

    /// Bump the transaction sequence number after a commit lands.
    /// # C: O(1)
    pub fn bump_seq(&mut self) { self.seq = self.seq.wrapping_add(1); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::descriptor::DescriptorIter;

    fn s(target_lba: u64, byte: u8, bs: usize) -> StagedBlock {
        StagedBlock { target_lba, data: alloc::vec![byte; bs] }
    }

    const UUID: [u8; 16] = [0xA5; 16];

    fn transaction(seq: u32, staged: &[StagedBlock], bs: usize) -> std::vec::Vec<std::vec::Vec<u8>> {
        let mut out = std::vec::Vec::new();
        emit_transaction(seq, staged, bs, false, &UUID, |block| {
            out.push(block.to_vec());
            Ok::<(), ()>(())
        }).unwrap();
        out
    }

    #[test]
    fn descriptor_round_trips_through_iter() {
        let bs = 1024;
        let blocks = std::vec![s(7, 0xAA, bs), s(42, 0xBB, bs), s(100, 0xCC, bs)];
        let dbuf = build_descriptor_block(5, &blocks, bs, false, &UUID).unwrap();
        let header = BlockHeader::parse(&dbuf).unwrap();
        assert_eq!(header.block_type, BlockType::Descriptor);
        assert_eq!(header.sequence, 5);
        let tags: std::vec::Vec<_> = DescriptorIter::new(&dbuf[12..], false).collect();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].tag.blocknr, 7);
        assert_eq!(tags[2].tag.blocknr, 100);
        assert_eq!(tags[0].tag.flags & TAG_FLAG_SAME_UUID, 0);
        assert_ne!(tags[1].tag.flags & TAG_FLAG_SAME_UUID, 0);
        assert!((tags[2].tag.flags & TAG_FLAG_LAST) != 0);
        assert_eq!(&dbuf[20..36], &UUID);
    }

    #[test]
    fn descriptor_marks_escape_on_magic_collision() {
        let bs = 64;
        let mut data = alloc::vec![0u8; bs];
        data[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        let blocks = std::vec![StagedBlock { target_lba: 7, data }];
        let dbuf = build_descriptor_block(1, &blocks, 1024, false, &UUID).unwrap();
        let tags: std::vec::Vec<_> = DescriptorIter::new(&dbuf[12..], false).collect();
        assert!((tags[0].tag.flags & TAG_FLAG_ESCAPE) != 0,
                "first-4-byte magic collision triggers ESCAPE");
    }

    #[test]
    fn descriptor_round_trips_64bit_target() {
        let target = 0x0000_0001_0000_0064;
        let dbuf = build_descriptor_block(3, &[s(target, 0xCC, 1024)], 1024, true, &UUID).unwrap();
        let tags: std::vec::Vec<_> = DescriptorIter::new(&dbuf[12..], true).collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].tag.blocknr, target);
        assert_eq!(&dbuf[24..40], &UUID);
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
        let mut c = LogCursor::new(1, 1, 8, 1);
        assert_eq!(c.reserve(3), 1); assert_eq!(c.head, 4);
        assert_eq!(c.reserve(3), 4); assert_eq!(c.head, 7);
        // 7 + 3 = 10; maxlen 8; should wrap.
        let r = c.reserve(3);
        assert_eq!(r, 7);
        assert!(c.head < 8 && c.head != 0, "wrapped, never zero");
    }

    #[test]
    fn log_cursor_wraps_to_superblock_first_not_one() {
        let mut c = LogCursor::new(0, 4, 10, 1);
        assert_eq!(c.usable(), 6);
        assert_eq!(c.reserve(5), 4);
        assert_eq!(c.head, 9);
        assert_eq!(c.reserve(1), 9);
        assert_eq!(c.head, 4);
    }

    #[test]
    fn descriptor_then_data_then_commit_replays_through_replay() {
        // End-to-end: build descriptor + commit + data, hand them
        // to replay::replay against a memory-backed disk, observe
        // the target writes apply.
        use super::super::replay::{replay, JournalLogReader, ReplayError};
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
        let mut blocks: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
        blocks.push(alloc::vec![0u8; bs]);  // index 0 = sb pad
        blocks.extend(transaction(7, &staged, bs));
        let j = VecJournal(blocks);
        let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 32);
        let sb = super::super::JournalSuperblock {
            block_size: bs as u32, maxlen: 32, first: 1, sequence: 7, start: 1,
            feature_compat: 0, feature_incompat: 0, feature_ro: 0, uuid: UUID,
        };
        let stats = replay(&j, &*disk, &sb).unwrap();
        assert_eq!(stats.txns_replayed, 1);
        assert_eq!(stats.blocks_applied, 2);
    }

    #[test]
    fn full_batch_splits_descriptors_and_replays_one_transaction() {
        use super::super::replay::{replay, JournalLogReader, ReplayError};
        use sync::TaskList;
        use block::{BlockDevice, BlockRequest, MemDisk};
        use alloc::sync::Arc;

        struct VecJournal(std::vec::Vec<std::vec::Vec<u8>>);
        impl JournalLogReader for VecJournal {
            fn read_journal_block(&self, jblk: u32) -> Result<std::vec::Vec<u8>, ReplayError> {
                self.0.get(jblk as usize).cloned().ok_or(ReplayError::BlockIo)
            }
        }

        let bs = 4096usize;
        let cap = descriptor_capacity(bs, false);
        assert_eq!(cap, 508);
        let staged: std::vec::Vec<_> = (0..512u64)
            .map(|lba| s(lba, (lba % 251) as u8, bs))
            .collect();
        let tx = transaction(9, &staged, bs);
        assert_eq!(tx.len(), 515, "two descriptors + 512 payloads + commit");
        let first: std::vec::Vec<_> = DescriptorIter::new(&tx[0][12..], false).collect();
        let second: std::vec::Vec<_> = DescriptorIter::new(&tx[cap + 1][12..], false).collect();
        assert_eq!(first.len(), cap);
        assert_eq!(second.len(), 512 - cap);
        assert_ne!(first.last().unwrap().tag.flags & TAG_FLAG_LAST, 0);
        assert_ne!(second.last().unwrap().tag.flags & TAG_FLAG_LAST, 0);

        let mut blocks = std::vec![alloc::vec![0u8; bs]];
        blocks.extend(tx);
        let maxlen = blocks.len() as u32 + 1;
        let journal = VecJournal(blocks);
        let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 512);
        let sb = super::super::JournalSuperblock {
            block_size: bs as u32, maxlen, first: 1, sequence: 9, start: 1,
            feature_compat: 0, feature_incompat: 0, feature_ro: 0, uuid: UUID,
        };
        let stats = replay(&journal, &*disk, &sb).unwrap();
        assert_eq!(stats.txns_replayed, 1);
        assert_eq!(stats.blocks_applied, 512);
        for lba in [0u64, 507, 508, 511] {
            let mut req = BlockRequest::new_read(lba, 1, bs as u32);
            disk.submit_sync(&mut req).unwrap();
            assert_eq!(req.buffer[0], (lba % 251) as u8, "target {lba}");
        }
    }

    #[test]
    fn transaction_wraps_at_superblock_first_and_replays() {
        use super::super::replay::{replay, JournalLogReader, ReplayError};
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
        let staged = [s(7, 0xBC, bs)];
        let tx = transaction(11, &staged, bs);
        let mut blocks = std::vec![alloc::vec![0u8; bs]; 20];
        let mut cursor = LogCursor::new(18, 4, 20, 11);
        for block in tx {
            let at = cursor.reserve(1);
            blocks[at as usize] = block;
        }
        assert_eq!(BlockHeader::parse(&blocks[4]).unwrap().block_type, BlockType::Commit);
        assert!(BlockHeader::parse(&blocks[1]).is_err(), "reserved prefix stays untouched");
        let journal = VecJournal(blocks);
        let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 16);
        let sb = super::super::JournalSuperblock {
            block_size: bs as u32, maxlen: 20, first: 4, sequence: 11, start: 18,
            feature_compat: 0, feature_incompat: 0, feature_ro: 0, uuid: UUID,
        };
        let stats = replay(&journal, &*disk, &sb).unwrap();
        assert_eq!(stats.txns_replayed, 1);
        assert_eq!(stats.blocks_applied, 1);
    }
}
