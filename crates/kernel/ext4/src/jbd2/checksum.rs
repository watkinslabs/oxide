// JBD2 checksum formats. Linux supports the original compatible transaction
// CRC32 and the mutually-exclusive v2/v3 crc32c formats.

use crc::{crc32_be_update, crc32c_update};

pub const JBD2_CRC32_CHKSUM: u8 = 1;
pub const JBD2_CRC32_CHKSUM_SIZE: u8 = 4;
pub const JBD2_CRC32C_CHKSUM: u8 = 4;

pub const COMMIT_CHECKSUM_OFFSET: usize = 16;
pub const SUPERBLOCK_CHECKSUM_OFFSET: usize = 0xFC;
pub const SUPERBLOCK_BYTES: usize = 1024;
pub const BLOCK_TAIL_BYTES: usize = 4;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ChecksumMode {
    None,
    V1,
    V2,
    V3,
}

impl ChecksumMode {
    /// # C: O(1)
    pub fn has_block_checksums(self) -> bool {
        matches!(self, Self::V2 | Self::V3)
    }
}

/// Linux `j_csum_seed = crc32c(~0, journal_uuid)`.
/// # C: O(1)
pub fn checksum_seed(uuid: &[u8; 16]) -> u32 {
    crc32c_update(0xFFFF_FFFF, uuid)
}

/// Linux checksum-v2/v3 per-tag crc32c over `be32(sequence) + payload`, seeded
/// by the journal UUID checksum. `payload` is the escaped on-log block.
/// # C: O(block_size)
pub fn data_checksum(seed: u32, sequence: u32, payload: &[u8]) -> u32 {
    let csum = crc32c_update(seed, &sequence.to_be_bytes());
    crc32c_update(csum, payload)
}

/// Compute a crc32c over a block while treating its stored checksum word as
/// zero, as JBD2 does for descriptor, revoke, commit, and superblock checksums.
/// # C: O(block_size)
pub fn checksum_with_zeroed_word(seed: u32, block: &[u8], offset: usize) -> Option<u32> {
    if offset.checked_add(4)? > block.len() { return None; }
    let csum = crc32c_update(seed, &block[..offset]);
    let csum = crc32c_update(csum, &[0u8; 4]);
    Some(crc32c_update(csum, &block[offset + 4..]))
}

/// Verify a big-endian checksum word embedded in `block`.
/// # C: O(block_size)
pub fn verify_zeroed_word(seed: u32, block: &[u8], offset: usize) -> bool {
    let Some(end) = offset.checked_add(4) else { return false; };
    if end > block.len() { return false; }
    let provided = u32::from_be_bytes([
        block[offset], block[offset + 1], block[offset + 2], block[offset + 3],
    ]);
    checksum_with_zeroed_word(seed, block, offset) == Some(provided)
}

/// Stamp a big-endian checksum word embedded in `block`.
/// # C: O(block_size)
pub fn stamp_zeroed_word(seed: u32, block: &mut [u8], offset: usize) -> bool {
    let Some(csum) = checksum_with_zeroed_word(seed, block, offset) else { return false; };
    block[offset..offset + 4].copy_from_slice(&csum.to_be_bytes());
    true
}

/// Linux checksum-v1 transaction CRC (`crc32_be(~0, descriptor + payloads)`).
/// # C: O(block_size)
pub fn transaction_checksum_update(csum: u32, block: &[u8]) -> u32 {
    crc32_be_update(csum, block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroed_word_round_trip_and_corruption() {
        let mut block = [0xA5u8; 64];
        assert!(stamp_zeroed_word(0x1234_5678, &mut block, 16));
        assert!(verify_zeroed_word(0x1234_5678, &block, 16));
        block[31] ^= 1;
        assert!(!verify_zeroed_word(0x1234_5678, &block, 16));
    }

    #[test]
    fn data_checksum_includes_sequence() {
        let seed = checksum_seed(&[0x11; 16]);
        assert_ne!(data_checksum(seed, 7, &[0x22; 32]),
                   data_checksum(seed, 8, &[0x22; 32]));
    }
}
