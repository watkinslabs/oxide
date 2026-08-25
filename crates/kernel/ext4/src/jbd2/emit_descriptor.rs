extern crate alloc;

use alloc::vec::Vec;

use super::super::block_header::{BlockHeader, BlockType, JBD2_MAGIC};
use super::super::checksum::{self, ChecksumMode};
use super::super::descriptor::{TAG_FLAG_ESCAPE, TAG_FLAG_LAST, TAG_FLAG_SAME_UUID};
use super::{EmitError, StagedBlock};

const HEADER_BYTES: usize = 12;
const TAG32_BYTES: usize = 8;
const TAG64_BYTES: usize = 12;
const TAG_V2_32_BYTES: usize = 10;
const TAG_V2_64_BYTES: usize = 14;
const TAG_V3_BYTES: usize = 16;
const UUID_BYTES: usize = 16;

/// Maximum unchecksummed tags one descriptor can encode.
/// # C: O(1)
pub fn descriptor_capacity(block_size: usize, bit64: bool) -> usize {
    descriptor_capacity_for(block_size, bit64, ChecksumMode::None)
}

/// Maximum tags for the exact feature-selected on-disk layout.
/// # C: O(1)
pub fn descriptor_capacity_for(block_size: usize, bit64: bool, checksum_mode: ChecksumMode) -> usize {
    let tag = descriptor_tag_bytes(bit64, checksum_mode);
    let tail = if checksum_mode.has_block_checksums() { checksum::BLOCK_TAIL_BYTES } else { 0 };
    block_size.saturating_sub(HEADER_BYTES + UUID_BYTES + tail) / tag
}

/// # C: O(1)
fn descriptor_tag_bytes(bit64: bool, checksum_mode: ChecksumMode) -> usize {
    match checksum_mode {
        ChecksumMode::V3 => TAG_V3_BYTES,
        ChecksumMode::V2 => if bit64 { TAG_V2_64_BYTES } else { TAG_V2_32_BYTES },
        ChecksumMode::None | ChecksumMode::V1 => if bit64 { TAG64_BYTES } else { TAG32_BYTES },
    }
}

/// Build the unchecksummed on-disk descriptor block for one transaction.
/// # C: O(N tags)
pub fn build_descriptor_block(
    seq: u32, staged: &[StagedBlock], block_size: usize, bit64: bool,
    uuid: &[u8; UUID_BYTES],
) -> Result<Vec<u8>, EmitError> {
    build_descriptor_block_for(seq, staged, block_size, bit64, uuid, ChecksumMode::None, 0)
}

/// Build a descriptor using the selected tag and checksum layout.
/// # C: O(N tags * block_size) for v2/v3 data checksums
pub fn build_descriptor_block_for(
    seq: u32, staged: &[StagedBlock], block_size: usize, bit64: bool,
    uuid: &[u8; UUID_BYTES], checksum_mode: ChecksumMode, checksum_seed: u32,
) -> Result<Vec<u8>, EmitError> {
    let cap = descriptor_capacity_for(block_size, bit64, checksum_mode);
    if staged.is_empty() { return Err(EmitError::Empty); }
    if cap == 0 || staged.len() > cap { return Err(EmitError::BlockSize); }
    let mut buf = alloc::vec![0u8; block_size];
    BlockHeader { block_type: BlockType::Descriptor, sequence: seq }.write_to(&mut buf);
    let tag_bytes = descriptor_tag_bytes(bit64, checksum_mode);
    let mut off = HEADER_BYTES;
    for (i, s) in staged.iter().enumerate() {
        if !bit64 && s.target_lba > u32::MAX as u64 { return Err(EmitError::BlockNumber); }
        let mut flags = if i == 0 { 0 } else { TAG_FLAG_SAME_UUID };
        if i == staged.len() - 1 { flags |= TAG_FLAG_LAST; }
        let escape = if s.data.len() >= 4 {
            u32::from_be_bytes([s.data[0], s.data[1], s.data[2], s.data[3]]) == JBD2_MAGIC
        } else { false };
        if escape { flags |= TAG_FLAG_ESCAPE; }
        buf[off..off + 4].copy_from_slice(&(s.target_lba as u32).to_be_bytes());
        if checksum_mode == ChecksumMode::V3 {
            buf[off + 4..off + 8].copy_from_slice(&flags.to_be_bytes());
            buf[off + 8..off + 12].copy_from_slice(&((s.target_lba >> 32) as u32).to_be_bytes());
            let csum = staged_data_checksum(checksum_seed, seq, s, block_size);
            buf[off + 12..off + 16].copy_from_slice(&csum.to_be_bytes());
        } else {
            if checksum_mode == ChecksumMode::V2 {
                let csum = staged_data_checksum(checksum_seed, seq, s, block_size);
                buf[off + 4..off + 6].copy_from_slice(&(csum as u16).to_be_bytes());
            }
            buf[off + 6..off + 8].copy_from_slice(&(flags as u16).to_be_bytes());
            if bit64 { buf[off + 8..off + 12].copy_from_slice(&((s.target_lba >> 32) as u32).to_be_bytes()); }
        }
        off += tag_bytes;
        if i == 0 { buf[off..off + UUID_BYTES].copy_from_slice(uuid); off += UUID_BYTES; }
    }
    if checksum_mode.has_block_checksums() {
        let tail = block_size - checksum::BLOCK_TAIL_BYTES;
        if !checksum::stamp_zeroed_word(checksum_seed, &mut buf, tail) { return Err(EmitError::BlockSize); }
    }
    Ok(buf)
}

fn staged_data_checksum(seed: u32, seq: u32, staged: &StagedBlock, block_size: usize) -> u32 {
    let mut csum = crc::crc32c_update(seed, &seq.to_be_bytes());
    let used = core::cmp::min(staged.data.len(), block_size);
    let escaped = used >= 4
        && u32::from_be_bytes([staged.data[0], staged.data[1], staged.data[2], staged.data[3]]) == JBD2_MAGIC;
    let mut off = 0usize;
    if escaped { csum = crc::crc32c_update(csum, &[0u8; 4]); off = 4; }
    csum = crc::crc32c_update(csum, &staged.data[off..used]);
    const ZEROES: [u8; 64] = [0; 64];
    let mut remaining = block_size - used;
    while remaining != 0 {
        let n = core::cmp::min(remaining, ZEROES.len());
        csum = crc::crc32c_update(csum, &ZEROES[..n]);
        remaining -= n;
    }
    csum
}

/// Replace a leading journal magic word before writing a payload.
/// # C: O(1)
pub fn escape_journal_payload(data: &mut [u8]) {
    if data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == JBD2_MAGIC {
        data[0..4].copy_from_slice(&0u32.to_be_bytes());
    }
}
