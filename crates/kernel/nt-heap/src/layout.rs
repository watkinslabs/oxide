//! Eight-byte block header stored in front of every returned data pointer.

use crate::flags::BLOCK_FLAG_FREE;
use crate::limits::BLOCK_ALIGN;

/// Region index recorded by a block that owns its own mapping.
pub const LARGE_REGION: u16 = u16::MAX;

/// Header preceding a block body: size in `BLOCK_ALIGN` units, unused tail
/// bytes, owning region index, type and flag bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Header { pub block_size: usize, pub tail: usize, pub region: u16, pub kind: u8, pub flags: u8 }

impl Header {
    /// Decode a header from its stored bytes.
    /// # C: O(1)
    pub fn decode(bytes: [u8; 8]) -> Header {
        let low = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let tail = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let region = u16::from_le_bytes([bytes[4], bytes[5]]);
        let flags = bytes[7];
        // A free block spends the tail field on the high size bits, so a whole
        // free region larger than the used-block ceiling still round-trips.
        let units = if flags & BLOCK_FLAG_FREE != 0 { low | (tail << 16) } else { low };
        let tail = if flags & BLOCK_FLAG_FREE != 0 { 0 } else { tail };
        Header { block_size: units * BLOCK_ALIGN, tail, region, kind: bytes[6], flags }
    }

    /// Encode a header to its stored bytes.
    /// # C: O(1)
    pub fn encode(&self) -> [u8; 8] {
        let units = self.block_size / BLOCK_ALIGN;
        let (low, tail) = if self.flags & BLOCK_FLAG_FREE != 0 { (units & 0xffff, units >> 16) } else { (units & 0xffff, self.tail) };
        let mut bytes = [0u8; 8];
        bytes[0..2].copy_from_slice(&(low as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&(tail as u16).to_le_bytes());
        bytes[4..6].copy_from_slice(&self.region.to_le_bytes());
        bytes[6] = self.kind;
        bytes[7] = self.flags;
        bytes
    }

    /// User bytes this allocated block serves.
    /// # C: O(1)
    pub fn user_size(&self) -> usize { self.block_size - crate::limits::HEADER_BYTES - self.tail }
}
