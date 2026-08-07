// JBD2 replay: walk the journal from `sb.start`, collecting
// descriptor → data → commit triples and applying them to the
// underlying fs device. Stops at the first invalid block (no
// magic / wrong sequence) or when the log wraps to the start
// of an unsequenced transaction.
//
// Real JBD2 uses a 3-pass scan (PASS_SCAN, PASS_REVOKE,
// PASS_REPLAY) to honour revoke records before applying log
// data. v1 implements the same shape; revoke handling is
// minimal (the in-memory revoke table is consulted during
// PASS_REPLAY).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use block::{BlockDevice, BlockRequest, types::BlockError};

use super::block_header::{BlockHeader, BlockType, JBD2_MAGIC};
use super::checksum::{self, ChecksumMode};
use super::descriptor::{DescriptorIter, DescriptorTag, TAG_FLAG_ESCAPE, TAG_FLAG_LAST};
use super::superblock::{JournalSuperblock, JBD2_INCOMPAT_64BIT, JBD2_INCOMPAT_REVOKE};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReplayError {
    BlockIo,
    Corrupt,
    BadChecksum,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplayStats {
    pub txns_replayed:  u32,
    pub blocks_applied: u32,
    pub revokes:        u32,
}

/// Trait the journal uses to map "journal block index" → physical
/// device LBA. The ext4 mount supplies this via its journal
/// inode's extent walk.
pub trait JournalLogReader {
    /// Read `len` bytes starting at journal-block index `jblk`.
    /// `len` is always exactly `journal_sb.block_size`.
    fn read_journal_block(&self, jblk: u32) -> Result<Vec<u8>, ReplayError>;
}

/// Run the JBD2 replay against `journal` (logical reader) +
/// `target` (the fs block device the journal recovers to).
/// `target_block_size` is the fs's own block size (= journal
/// block size when the journal is internal, which is the
/// only mode v1 supports).
/// # C: O(journal_size / block_size) I/O
pub fn replay<J: JournalLogReader>(
    journal:           &J,
    target:            &dyn BlockDevice,
    sb:                &JournalSuperblock,
) -> Result<ReplayStats, ReplayError> {
    let bit64    = (sb.feature_incompat & JBD2_INCOMPAT_64BIT)     != 0;
    let _revoke_on = (sb.feature_incompat & JBD2_INCOMPAT_REVOKE) != 0;
    let checksum_mode = sb.checksum_mode();
    let checksum_seed = checksum::checksum_seed(&sb.uuid);
    let mut stats = ReplayStats::default();
    if !sb.needs_recovery() { return Ok(stats); }

    // Pass 1: scan revokes; track (blocknr, sequence-of-revoke).
    let mut revoke_set: BTreeMap<u64, u32> = BTreeMap::new();
    let mut cur = sb.start;
    let mut seq = sb.sequence;
    let mut transaction_csum = 0xFFFF_FFFF;
    loop {
        let blk = match journal.read_journal_block(cur) {
            Ok(b) => b, Err(_) => break,
        };
        let header = match BlockHeader::parse(&blk) {
            Ok(h) => h, Err(_) => break,
        };
        if header.sequence != seq {
            // Reached unsequenced data — end of log.
            break;
        }
        match header.block_type {
            BlockType::Descriptor => {
                let tags = descriptor_tags(&blk, bit64, checksum_mode, checksum_seed)?;
                if checksum_mode == ChecksumMode::V1 {
                    transaction_csum = checksum::transaction_checksum_update(transaction_csum, &blk);
                    let mut data_cur = wrap_advance(cur, 1, sb.first, sb.maxlen);
                    for _ in &tags {
                        let data = journal.read_journal_block(data_cur)
                            .map_err(|_| ReplayError::BlockIo)?;
                        transaction_csum = checksum::transaction_checksum_update(transaction_csum, &data);
                        data_cur = wrap_advance(data_cur, 1, sb.first, sb.maxlen);
                    }
                }
                // Skip past descriptor's data blocks for revoke pass.
                let n_data = tags.len() as u32;
                cur = wrap_advance(cur, 1 + n_data, sb.first, sb.maxlen);
            }
            BlockType::Commit => {
                if !verify_commit(&blk, checksum_mode, checksum_seed, transaction_csum) {
                    return Err(ReplayError::BadChecksum);
                }
                transaction_csum = 0xFFFF_FFFF;
                seq = seq.wrapping_add(1);
                cur = wrap_advance(cur, 1, sb.first, sb.maxlen);
            }
            BlockType::Revoke => {
                if checksum_mode.has_block_checksums()
                    && !verify_block_tail(&blk, checksum_seed)
                {
                    return Err(ReplayError::BadChecksum);
                }
                if blk.len() < 16 { return Err(ReplayError::Corrupt); }
                let count_bytes = u32::from_be_bytes([blk[12], blk[13], blk[14], blk[15]]) as usize;
                let block_end = blk.len().saturating_sub(
                    if checksum_mode.has_block_checksums() { checksum::BLOCK_TAIL_BYTES } else { 0 },
                );
                if count_bytes < 16 || count_bytes > block_end {
                    return Err(ReplayError::Corrupt);
                }
                let payload = &blk[16..count_bytes];
                let stride = if bit64 { 8 } else { 4 };
                let mut o = 0usize;
                while o + stride <= payload.len() {
                    let bn = if bit64 {
                        u64::from_be_bytes([
                            payload[o], payload[o+1], payload[o+2], payload[o+3],
                            payload[o+4], payload[o+5], payload[o+6], payload[o+7],
                        ])
                    } else {
                        u32::from_be_bytes([payload[o], payload[o+1], payload[o+2], payload[o+3]]) as u64
                    };
                    match revoke_set.get_mut(&bn) {
                        Some(old) if tid_gt(seq, *old) => { *old = seq; }
                        None => { revoke_set.insert(bn, seq); }
                        _ => {}
                    }
                    stats.revokes += 1;
                    o += stride;
                }
                cur = wrap_advance(cur, 1, sb.first, sb.maxlen);
            }
            BlockType::SuperblockV1 | BlockType::SuperblockV2 => {
                cur = wrap_advance(cur, 1, sb.first, sb.maxlen);
            }
        }
        if cur == sb.start { break; }
    }

    // Pass 2: replay descriptor → data → commit.
    let mut cur = sb.start;
    let mut seq = sb.sequence;
    let mut pending: Vec<(u64, Vec<u8>)> = Vec::new();
    loop {
        let blk = match journal.read_journal_block(cur) {
            Ok(b) => b, Err(_) => break,
        };
        let header = match BlockHeader::parse(&blk) {
            Ok(h) => h, Err(_) => break,
        };
        if header.sequence != seq { break; }
        match header.block_type {
            BlockType::Descriptor => {
                let tags = descriptor_tags(&blk, bit64, checksum_mode, checksum_seed)?;
                cur = wrap_advance(cur, 1, sb.first, sb.maxlen);
                for tag in &tags {
                    let data = match journal.read_journal_block(cur) {
                        Ok(b) => b, Err(_) => return Err(ReplayError::Corrupt),
                    };
                    cur = wrap_advance(cur, 1, sb.first, sb.maxlen);
                    if checksum_mode.has_block_checksums() {
                        let actual = checksum::data_checksum(checksum_seed, seq, &data);
                        let matches = if checksum_mode == ChecksumMode::V2 {
                            tag.checksum == (actual as u16) as u32
                        } else {
                            tag.checksum == actual
                        };
                        if !matches { return Err(ReplayError::BadChecksum); }
                    }
                    let mut payload = data;
                    // ESCAPE: first 4 bytes of the data block were
                    // overwritten to 0 because they would otherwise
                    // collide with JBD2_MAGIC. Restore.
                    if (tag.flags & TAG_FLAG_ESCAPE) != 0 {
                        if payload.len() >= 4 {
                            payload[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
                        }
                    }
                    pending.push((tag.blocknr, payload));
                    if (tag.flags & TAG_FLAG_LAST) != 0 { break; }
                }
            }
            BlockType::Commit => {
                if checksum_mode != ChecksumMode::V1
                    && !verify_commit(&blk, checksum_mode, checksum_seed, 0)
                {
                    return Err(ReplayError::BadChecksum);
                }
                // Apply all pending blocks (filtered by revoke set).
                let bs = sb.block_size as u64;
                for (bn, data) in pending.drain(..) {
                    if revoke_set.get(&bn).map_or(false, |&revoke_seq| !tid_gt(seq, revoke_seq)) {
                        continue;
                    }
                    write_target(target, bn * bs, &data)?;
                    stats.blocks_applied += 1;
                }
                stats.txns_replayed += 1;
                seq = seq.wrapping_add(1);
                cur = wrap_advance(cur, 1, sb.first, sb.maxlen);
            }
            BlockType::Revoke => {
                if checksum_mode.has_block_checksums()
                    && !verify_block_tail(&blk, checksum_seed)
                {
                    return Err(ReplayError::BadChecksum);
                }
                cur = wrap_advance(cur, 1, sb.first, sb.maxlen);
            }
            BlockType::SuperblockV1 | BlockType::SuperblockV2 => {
                cur = wrap_advance(cur, 1, sb.first, sb.maxlen);
            }
        }
        if cur == sb.start { break; }
    }
    Ok(stats)
}

fn descriptor_tags(
    block: &[u8],
    bit64: bool,
    checksum_mode: ChecksumMode,
    checksum_seed: u32,
) -> Result<Vec<DescriptorTag>, ReplayError> {
    let tail = if checksum_mode.has_block_checksums() {
        if !verify_block_tail(block, checksum_seed) { return Err(ReplayError::BadChecksum); }
        checksum::BLOCK_TAIL_BYTES
    } else { 0 };
    if block.len() < 12 + tail { return Err(ReplayError::Corrupt); }
    let tags: Vec<_> = DescriptorIter::with_checksum(
        &block[12..block.len() - tail], bit64, checksum_mode,
    ).map(|entry| entry.tag).collect();
    if tags.is_empty() || tags.last().map_or(true, |tag| tag.flags & TAG_FLAG_LAST == 0) {
        return Err(ReplayError::Corrupt);
    }
    Ok(tags)
}

fn verify_block_tail(block: &[u8], checksum_seed: u32) -> bool {
    block.len() >= checksum::BLOCK_TAIL_BYTES
        && checksum::verify_zeroed_word(
            checksum_seed, block, block.len() - checksum::BLOCK_TAIL_BYTES,
        )
}

fn verify_commit(
    block: &[u8],
    checksum_mode: ChecksumMode,
    checksum_seed: u32,
    transaction_checksum: u32,
) -> bool {
    if block.len() < checksum::COMMIT_CHECKSUM_OFFSET + 4 { return false; }
    let provided = u32::from_be_bytes([
        block[checksum::COMMIT_CHECKSUM_OFFSET],
        block[checksum::COMMIT_CHECKSUM_OFFSET + 1],
        block[checksum::COMMIT_CHECKSUM_OFFSET + 2],
        block[checksum::COMMIT_CHECKSUM_OFFSET + 3],
    ]);
    match checksum_mode {
        ChecksumMode::None => true,
        ChecksumMode::V1 => {
            (block[12] == checksum::JBD2_CRC32_CHKSUM
                && block[13] == checksum::JBD2_CRC32_CHKSUM_SIZE
                && provided == transaction_checksum)
                || (block[12] == 0 && block[13] == 0 && provided == 0)
        }
        ChecksumMode::V2 | ChecksumMode::V3 => checksum::verify_zeroed_word(
            checksum_seed, block, checksum::COMMIT_CHECKSUM_OFFSET,
        ),
    }
}

fn wrap_advance(cur: u32, delta: u32, first: u32, maxlen: u32) -> u32 {
    let first = core::cmp::max(first, 1);
    let range = maxlen.saturating_sub(first) as u64;
    if range == 0 { return cur; }
    let off = cur.saturating_sub(first) as u64;
    first + ((off + delta as u64) % range) as u32
}

fn tid_gt(x: u32, y: u32) -> bool { (x.wrapping_sub(y) as i32) > 0 }

fn write_target(target: &dyn BlockDevice, byte_off: u64, data: &[u8]) -> Result<(), ReplayError> {
    let bs = target.block_size() as u64;
    if byte_off % bs != 0 || data.len() as u64 % bs != 0 {
        return Err(ReplayError::Corrupt);
    }
    let start = byte_off / bs;
    let n = (data.len() as u64 / bs) as u32;
    let mut req = BlockRequest::new_write(start, n, data.to_vec());
    target.submit_sync(&mut req).map_err(|e| match e {
        BlockError::Eio | BlockError::Einval => ReplayError::BlockIo,
        _ => ReplayError::BlockIo,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::block_header::{BlockHeader, BlockType};
    use super::super::descriptor::{TAG_FLAG_LAST, TAG_FLAG_SAME_UUID};

    /// Hosted JournalLogReader backed by a Vec<Vec<u8>> (one
    /// entry per journal block index).
    struct MemJournal { blocks: std::vec::Vec<std::vec::Vec<u8>> }
    impl JournalLogReader for MemJournal {
        fn read_journal_block(&self, jblk: u32) -> Result<std::vec::Vec<u8>, ReplayError> {
            self.blocks.get(jblk as usize).cloned().ok_or(ReplayError::BlockIo)
        }
    }

    use sync::TaskList;
    use block::MemDisk;
    use alloc::sync::Arc;

    fn make_descriptor(seq: u32, target_blk: u64, bs: usize) -> std::vec::Vec<u8> {
        let mut b = std::vec![0u8; bs];
        BlockHeader { block_type: BlockType::Descriptor, sequence: seq }.write_to(&mut b);
        // One tag: target_blk, LAST | SAME_UUID (no UUID payload).
        // Since this is the first tag of the txn, real JBD2 emits
        // a UUID; for our test we set SAME_UUID upfront so our
        // parser doesn't try to consume 16 bytes of UUID.
        let off = 12;
        b[off..off+4].copy_from_slice(&(target_blk as u32).to_be_bytes());
        b[off+4..off+8].copy_from_slice(&(TAG_FLAG_SAME_UUID | TAG_FLAG_LAST).to_be_bytes());
        b
    }

    fn make_commit(seq: u32, bs: usize) -> std::vec::Vec<u8> {
        let mut b = std::vec![0u8; bs];
        BlockHeader { block_type: BlockType::Commit, sequence: seq }.write_to(&mut b);
        b
    }

    fn make_revoke(seq: u32, target_blk: u32, bs: usize) -> std::vec::Vec<u8> {
        let mut b = std::vec![0u8; bs];
        BlockHeader { block_type: BlockType::Revoke, sequence: seq }.write_to(&mut b);
        b[12..16].copy_from_slice(&20u32.to_be_bytes());
        b[16..20].copy_from_slice(&target_blk.to_be_bytes());
        b
    }

    fn make_data(byte: u8, bs: usize) -> std::vec::Vec<u8> { std::vec![byte; bs] }

    fn make_journal_sb(start: u32, sequence: u32, bs: u32, maxlen: u32) -> JournalSuperblock {
        JournalSuperblock {
            block_size: bs, maxlen, first: 1, sequence, start,
            feature_compat: 0, feature_incompat: 0, feature_ro: 0, uuid: [0u8; 16],
            checksum_type: 0,
        }
    }

    #[test]
    fn replay_no_recovery_when_clean() {
        let bs = 1024usize;
        let blocks = std::vec![make_data(0, bs)];
        let j = MemJournal { blocks };
        let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 16);
        let sb = make_journal_sb(0, 1, bs as u32, 16);
        let stats = replay(&j, &*disk, &sb).unwrap();
        assert_eq!(stats.txns_replayed, 0);
    }

    #[test]
    fn replay_one_txn_writes_to_target() {
        let bs = 1024usize;
        // journal: [sb_pad, descriptor, data, commit]
        let mut blocks = std::vec::Vec::new();
        blocks.push(make_data(0, bs));                             // index 0 (would be SB; never read)
        blocks.push(make_descriptor(5, 7, bs));                    // index 1
        blocks.push(make_data(0xAB, bs));                          // index 2 (data for blk 7)
        blocks.push(make_commit(5, bs));                           // index 3
        let j = MemJournal { blocks };
        let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 16);
        let sb = make_journal_sb(1, 5, bs as u32, 16);
        let stats = replay(&j, &*disk, &sb).unwrap();
        assert_eq!(stats.txns_replayed, 1);
        assert_eq!(stats.blocks_applied, 1);
        // Verify target block 7 now has 0xAB.
        let mut req = BlockRequest::new_read(7, 1, bs as u32);
        disk.submit_sync(&mut req).unwrap();
        assert_eq!(req.buffer[0], 0xAB);
    }

    #[test]
    fn later_transaction_survives_earlier_revoke_across_tid_wrap() {
        let bs = 1024usize;
        let old = u32::MAX;
        let new = 0;
        let blocks = std::vec![
            make_data(0, bs),
            make_descriptor(old, 7, bs),
            make_data(0xAA, bs),
            make_revoke(old, 7, bs),
            make_commit(old, bs),
            make_descriptor(new, 7, bs),
            make_data(0xBB, bs),
            make_commit(new, bs),
        ];
        let j = MemJournal { blocks };
        let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 16);
        let sb = make_journal_sb(1, old, bs as u32, 16);
        let stats = replay(&j, &*disk, &sb).unwrap();
        assert_eq!(stats.txns_replayed, 2);
        assert_eq!(stats.blocks_applied, 1, "revoke covers its txn, not a later one");
        let mut req = BlockRequest::new_read(7, 1, bs as u32);
        disk.submit_sync(&mut req).unwrap();
        assert_eq!(req.buffer[0], 0xBB);
    }
}
