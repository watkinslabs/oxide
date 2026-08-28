extern crate alloc;

use alloc::vec::Vec;

use super::super::block_header::{BlockHeader, BlockType};
use super::super::checksum::{self, ChecksumMode};
use super::descriptor::{build_descriptor_block_for, descriptor_capacity_for, escape_journal_payload};
use super::{EmitError, StagedBlock, TransactionError};

/// Journal slots occupied by one transaction.
/// # C: O(1)
pub fn transaction_block_count(staged_len: usize, block_size: usize, bit64: bool) -> Result<usize, EmitError> {
    transaction_block_count_for(staged_len, block_size, bit64, ChecksumMode::None)
}

/// Journal slots occupied by one transaction for the selected checksum layout.
/// # C: O(1)
pub fn transaction_block_count_for(
    staged_len: usize, block_size: usize, bit64: bool, checksum_mode: ChecksumMode,
) -> Result<usize, EmitError> {
    if staged_len == 0 { return Err(EmitError::Empty); }
    let cap = descriptor_capacity_for(block_size, bit64, checksum_mode);
    if cap == 0 { return Err(EmitError::BlockSize); }
    Ok(staged_len + staged_len.div_ceil(cap) + 1)
}

/// Stream one complete unchecksummed transaction in journal order.
/// # C: O(N staged blocks)
pub fn emit_transaction<E, F>(
    seq: u32, staged: &[StagedBlock], block_size: usize, bit64: bool,
    uuid: &[u8; 16], write: F,
) -> Result<(), TransactionError<E>>
where F: FnMut(&[u8]) -> Result<(), E> {
    emit_transaction_for(seq, staged, block_size, bit64, uuid, ChecksumMode::None, write)
}

/// Stream a complete transaction in the selected checksum format.
/// # C: O(N staged blocks)
pub fn emit_transaction_for<E, F>(
    seq: u32, staged: &[StagedBlock], block_size: usize, bit64: bool,
    uuid: &[u8; 16], checksum_mode: ChecksumMode, mut write: F,
) -> Result<(), TransactionError<E>>
where F: FnMut(&[u8]) -> Result<(), E> {
    transaction_block_count_for(staged.len(), block_size, bit64, checksum_mode)
        .map_err(TransactionError::Emit)?;
    let cap = descriptor_capacity_for(block_size, bit64, checksum_mode);
    let checksum_seed = checksum::checksum_seed(uuid);
    let mut transaction_csum = 0xFFFF_FFFF;
    for group in staged.chunks(cap) {
        let descriptor = build_descriptor_block_for(
            seq, group, block_size, bit64, uuid, checksum_mode, checksum_seed,
        ).map_err(TransactionError::Emit)?;
        if checksum_mode == ChecksumMode::V1 {
            transaction_csum = checksum::transaction_checksum_update(transaction_csum, &descriptor);
        }
        write(&descriptor).map_err(TransactionError::Write)?;
        for s in group {
            let mut data = s.data.clone();
            if data.len() != block_size { data.resize(block_size, 0); }
            escape_journal_payload(&mut data);
            if checksum_mode == ChecksumMode::V1 {
                transaction_csum = checksum::transaction_checksum_update(transaction_csum, &data);
            }
            write(&data).map_err(TransactionError::Write)?;
        }
    }
    let commit = build_commit_block_for(seq, block_size, checksum_mode, checksum_seed, transaction_csum);
    write(&commit).map_err(TransactionError::Write)
}

/// Emit the body and commit record through one sink. The boolean is false for
/// descriptor/data body blocks and true for the terminal commit block. The
/// split is intentional: Linux can post the commit record after posting all
/// body I/O, but before waiting for those body requests to finish.
pub fn emit_transaction_split<E, F>(
    seq: u32, staged: &[StagedBlock], block_size: usize, bit64: bool,
    uuid: &[u8; 16], checksum_mode: ChecksumMode, mut write: F,
) -> Result<(), TransactionError<E>>
where
    F: FnMut(bool, &[u8]) -> Result<(), E>,
{
    transaction_block_count_for(staged.len(), block_size, bit64, checksum_mode)
        .map_err(TransactionError::Emit)?;
    let cap = descriptor_capacity_for(block_size, bit64, checksum_mode);
    let checksum_seed = checksum::checksum_seed(uuid);
    let mut transaction_csum = 0xFFFF_FFFF;
    for group in staged.chunks(cap) {
        let descriptor = build_descriptor_block_for(
            seq, group, block_size, bit64, uuid, checksum_mode, checksum_seed,
        ).map_err(TransactionError::Emit)?;
        if checksum_mode == ChecksumMode::V1 {
            transaction_csum = checksum::transaction_checksum_update(transaction_csum, &descriptor);
        }
        write(false, &descriptor).map_err(TransactionError::Write)?;
        for s in group {
            let mut data = s.data.clone();
            if data.len() != block_size { data.resize(block_size, 0); }
            escape_journal_payload(&mut data);
            if checksum_mode == ChecksumMode::V1 {
                transaction_csum = checksum::transaction_checksum_update(transaction_csum, &data);
            }
            write(false, &data).map_err(TransactionError::Write)?;
        }
    }
    let commit = build_commit_block_for(seq, block_size, checksum_mode, checksum_seed, transaction_csum);
    write(true, &commit).map_err(TransactionError::Write)
}

/// Build an unchecksummed commit block.
/// # C: O(1)
pub fn build_commit_block(seq: u32, block_size: usize) -> Vec<u8> {
    build_commit_block_for(seq, block_size, ChecksumMode::None, 0, 0)
}

/// Build and checksum a commit block in the selected format.
/// # C: O(block_size) for v2/v3
pub fn build_commit_block_for(
    seq: u32, block_size: usize, checksum_mode: ChecksumMode,
    checksum_seed: u32, transaction_checksum: u32,
) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; block_size];
    BlockHeader { block_type: BlockType::Commit, sequence: seq }.write_to(&mut buf);
    if checksum_mode == ChecksumMode::V1 && block_size >= checksum::COMMIT_CHECKSUM_OFFSET + 4 {
        buf[12] = checksum::JBD2_CRC32_CHKSUM;
        buf[13] = checksum::JBD2_CRC32_CHKSUM_SIZE;
        buf[checksum::COMMIT_CHECKSUM_OFFSET..checksum::COMMIT_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&transaction_checksum.to_be_bytes());
    } else if checksum_mode.has_block_checksums() {
        let _ = checksum::stamp_zeroed_word(checksum_seed, &mut buf, checksum::COMMIT_CHECKSUM_OFFSET);
    }
    buf
}
