use super::*;
use super::super::{BlockHeader, BlockType, ChecksumMode, JBD2_MAGIC};
use super::super::descriptor::{DescriptorIter, TAG_FLAG_ESCAPE, TAG_FLAG_LAST, TAG_FLAG_SAME_UUID};
use super::super::checksum;

fn s(target_lba: u64, byte: u8, bs: usize) -> StagedBlock {
    StagedBlock { target_lba, data: alloc::vec![byte; bs] }
}

const UUID: [u8; 16] = [0xA5; 16];

fn transaction(seq: u32, staged: &[StagedBlock], bs: usize) -> std::vec::Vec<std::vec::Vec<u8>> {
    let mut out = std::vec::Vec::new();
    emit_transaction(seq, staged, bs, false, &UUID, |block| {
        out.push(block.to_vec()); Ok::<(), ()>(())
    }).unwrap();
    out
}

fn transaction_with_checksum(
    seq: u32, staged: &[StagedBlock], bs: usize, checksum_mode: ChecksumMode,
) -> std::vec::Vec<std::vec::Vec<u8>> {
    let mut out = std::vec::Vec::new();
    emit_transaction_for(seq, staged, bs, false, &UUID, checksum_mode, |block| {
        out.push(block.to_vec()); Ok::<(), ()>(())
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
    assert_ne!(tags[2].tag.flags & TAG_FLAG_LAST, 0);
    assert_eq!(&dbuf[20..36], &UUID);
}

#[test]
fn descriptor_marks_escape_on_magic_collision() {
    let bs = 64;
    let mut data = alloc::vec![0u8; bs];
    data[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    let blocks = [StagedBlock { target_lba: 7, data }];
    let dbuf = build_descriptor_block(1, &blocks, 1024, false, &UUID).unwrap();
    let tags: std::vec::Vec<_> = DescriptorIter::new(&dbuf[12..], false).collect();
    assert_ne!(tags[0].tag.flags & TAG_FLAG_ESCAPE, 0);
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
fn checksum_transactions_replay_and_reject_corruption() {
    use super::super::replay::{replay, JournalLogReader, ReplayError};
    use super::super::superblock::{JBD2_COMPAT_CHECKSUM, JBD2_INCOMPAT_CSUM_V2,
                                   JBD2_INCOMPAT_CSUM_V3};
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
    let seq = 23;
    let staged = [s(7, 0xBC, bs), s(8, 0xCD, bs)];
    for mode in [ChecksumMode::V1, ChecksumMode::V2, ChecksumMode::V3] {
        let tx = transaction_with_checksum(seq, &staged, bs, mode);
        let (feature_compat, feature_incompat, checksum_type) = match mode {
            ChecksumMode::V1 => (JBD2_COMPAT_CHECKSUM, 0, 0),
            ChecksumMode::V2 => (0, JBD2_INCOMPAT_CSUM_V2, checksum::JBD2_CRC32C_CHKSUM),
            ChecksumMode::V3 => (0, JBD2_INCOMPAT_CSUM_V3, checksum::JBD2_CRC32C_CHKSUM),
            ChecksumMode::None => unreachable!(),
        };
        let sb = super::super::JournalSuperblock {
            block_type: 4, block_size: bs as u32, maxlen: 16, first: 1, sequence: seq, start: 1,
            feature_compat, feature_incompat, feature_ro: 0, uuid: UUID, checksum_type,
        };
        let mut blocks = std::vec![alloc::vec![0u8; bs]];
        blocks.extend(tx.clone());
        let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 16);
        let stats = replay(&VecJournal(blocks), &*disk, &sb).unwrap();
        assert_eq!(stats.blocks_applied, 2, "{mode:?} clean transaction");
        for corrupt_index in [0usize, 1, tx.len() - 1] {
            let mut corrupt = tx.clone();
            let corrupt_byte = if mode == ChecksumMode::V1 && corrupt_index == tx.len() - 1 {
                checksum::COMMIT_CHECKSUM_OFFSET
            } else { 64 };
            corrupt[corrupt_index][corrupt_byte] ^= 1;
            let mut blocks = std::vec![alloc::vec![0u8; bs]];
            blocks.extend(corrupt);
            let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 16);
            assert_eq!(replay(&VecJournal(blocks), &*disk, &sb), Err(ReplayError::BadChecksum));
        }
    }
}

#[test]
fn log_cursor_reserves_and_wraps() {
    let mut c = LogCursor::new(1, 1, 8, 1);
    assert_eq!(c.reserve(3), 1); assert_eq!(c.head, 4);
    assert_eq!(c.reserve(3), 4); assert_eq!(c.head, 7);
    assert_eq!(c.reserve(3), 7);
    assert!(c.head < 8 && c.head != 0);
}

#[test]
fn log_cursor_wraps_to_superblock_first_not_one() {
    let mut c = LogCursor::new(0, 4, 10, 1);
    assert_eq!(c.usable(), 6);
    assert_eq!(c.reserve(5), 4); assert_eq!(c.head, 9);
    assert_eq!(c.reserve(1), 9); assert_eq!(c.head, 4);
}

#[test]
fn log_cursor_advances_sequence_after_a_committed_transaction() {
    let mut c = LogCursor::new(1, 1, 8, u32::MAX);
    c.bump_seq();
    assert_eq!(c.seq, 0, "JBD2 sequence numbers wrap at u32::MAX");
}

#[test]
fn descriptor_data_commit_replays() {
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
    let mut blocks = std::vec![alloc::vec![0u8; bs]];
    blocks.extend(transaction(7, &staged, bs));
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 32);
    let sb = super::super::JournalSuperblock {
        block_type: 4, block_size: bs as u32, maxlen: 32, first: 1, sequence: 7, start: 1,
        feature_compat: 0, feature_incompat: 0, feature_ro: 0, uuid: UUID, checksum_type: 0,
    };
    let stats = replay(&VecJournal(blocks), &*disk, &sb).unwrap();
    assert_eq!(stats.txns_replayed, 1); assert_eq!(stats.blocks_applied, 2);
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
    let staged: std::vec::Vec<_> = (0..512u64).map(|lba| s(lba, (lba % 251) as u8, bs)).collect();
    let tx = transaction(9, &staged, bs);
    assert_eq!(tx.len(), 515);
    let first: std::vec::Vec<_> = DescriptorIter::new(&tx[0][12..], false).collect();
    let second: std::vec::Vec<_> = DescriptorIter::new(&tx[cap + 1][12..], false).collect();
    assert_eq!(first.len(), cap); assert_eq!(second.len(), 512 - cap);
    assert_ne!(first.last().unwrap().tag.flags & TAG_FLAG_LAST, 0);
    assert_ne!(second.last().unwrap().tag.flags & TAG_FLAG_LAST, 0);
    let mut blocks = std::vec![alloc::vec![0u8; bs]];
    blocks.extend(tx);
    let maxlen = blocks.len() as u32 + 1;
    let journal = VecJournal(blocks);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 512);
    let sb = super::super::JournalSuperblock {
        block_type: 4, block_size: bs as u32, maxlen, first: 1, sequence: 9, start: 1,
        feature_compat: 0, feature_incompat: 0, feature_ro: 0, uuid: UUID, checksum_type: 0,
    };
    let stats = replay(&journal, &*disk, &sb).unwrap();
    assert_eq!(stats.txns_replayed, 1); assert_eq!(stats.blocks_applied, 512);
    for lba in [0u64, 507, 508, 511] {
        let mut req = BlockRequest::new_read(lba, 1, bs as u32);
        disk.submit_sync(&mut req).unwrap();
        assert_eq!(req.buffer[0], (lba % 251) as u8);
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
    let tx = transaction(11, &[s(7, 0xBC, bs)], bs);
    let mut blocks = std::vec![alloc::vec![0u8; bs]; 20];
    let mut cursor = LogCursor::new(18, 4, 20, 11);
    for block in tx { let at = cursor.reserve(1); blocks[at as usize] = block; }
    assert_eq!(BlockHeader::parse(&blocks[4]).unwrap().block_type, BlockType::Commit);
    assert!(BlockHeader::parse(&blocks[1]).is_err());
    let sb = super::super::JournalSuperblock {
        block_type: 4, block_size: bs as u32, maxlen: 20, first: 4, sequence: 11, start: 18,
        feature_compat: 0, feature_incompat: 0, feature_ro: 0, uuid: UUID, checksum_type: 0,
    };
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(bs as u32, 16);
    let stats = replay(&VecJournal(blocks), &*disk, &sb).unwrap();
    assert_eq!(stats.txns_replayed, 1); assert_eq!(stats.blocks_applied, 1);
}
