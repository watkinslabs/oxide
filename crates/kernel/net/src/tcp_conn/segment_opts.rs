//! Established TCP option assembly.

use alloc::vec::Vec;

use crate::tcp_hdr::{opt, SackBlock};

const TIMESTAMP_SPACE: usize = 12;
const SACK_PREFIX_SPACE: usize = 2;
const SACK_BLOCK_SPACE: usize = 8;
const MAX_SACK_BLOCKS: usize = 4;
const MAX_SACK_BLOCKS_WITH_TIMESTAMP: usize = 3;

/// Options carried by an established TCP segment. # C: O(1)
pub struct SegmentOptions<'a> {
    pub timestamp: Option<(u32, u32)>,
    pub sacks: &'a [SackBlock],
}

impl SegmentOptions<'_> {
    fn sacks(&self) -> &[SackBlock] {
        let max = if self.timestamp.is_some() {
            MAX_SACK_BLOCKS_WITH_TIMESTAMP
        } else {
            MAX_SACK_BLOCKS
        };
        &self.sacks[..self.sacks.len().min(max)]
    }

    /// Bytes occupied by the packed option area. # C: O(sacks)
    pub fn encoded_len(&self) -> usize {
        let timestamp = self.timestamp.map_or(0, |_| TIMESTAMP_SPACE);
        let sacks = self.sacks();
        if sacks.is_empty() { return timestamp; }
        let sack = SACK_PREFIX_SPACE + SACK_BLOCK_SPACE * sacks.len();
        if timestamp == 0 { (2 + sack + 3) & !3 } else { (timestamp + sack + 3) & !3 }
    }

    /// Encode timestamp then SACK blocks using TCP's established ordering. # C: O(sacks)
    pub fn encode(&self, out: &mut [u8]) -> usize {
        let len = self.encoded_len();
        if out.len() < len { return 0; }
        let mut i = 0;
        if let Some((tsval, tsecr)) = self.timestamp {
            out[..2].copy_from_slice(&[opt::NOP, opt::NOP]);
            out[2..4].copy_from_slice(&[opt::TIMESTAMP, 10]);
            out[4..8].copy_from_slice(&tsval.to_be_bytes());
            out[8..12].copy_from_slice(&tsecr.to_be_bytes());
            i = TIMESTAMP_SPACE;
        }
        let sacks = self.sacks();
        if !sacks.is_empty() {
            if i == 0 { out[..2].copy_from_slice(&[opt::NOP, opt::NOP]); i = 2; }
            out[i] = opt::SACK;
            out[i + 1] = (SACK_PREFIX_SPACE + SACK_BLOCK_SPACE * sacks.len()) as u8;
            i += SACK_PREFIX_SPACE;
            for block in sacks {
                out[i..i + 4].copy_from_slice(&block.left.to_be_bytes());
                out[i + 4..i + 8].copy_from_slice(&block.right.to_be_bytes());
                i += SACK_BLOCK_SPACE;
            }
        }
        for byte in &mut out[i..len] { *byte = opt::NOP; }
        len
    }
}

/// Copy an established option area into a complete TCP segment. # C: O(options + payload)
pub fn append(timestamp: Option<(u32, u32)>, sacks: &[SackBlock], payload: &[u8]) -> Vec<u8> {
    let options = SegmentOptions { timestamp, sacks };
    let mut bytes = alloc::vec![0; options.encoded_len() + payload.len()];
    let used = options.encode(&mut bytes);
    bytes[used..].copy_from_slice(payload);
    bytes
}

#[cfg(test)]
#[path = "segment_opts_tests.rs"]
mod tests;
