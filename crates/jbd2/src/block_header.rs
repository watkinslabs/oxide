// 12-byte JBD2 block header at offset 0 of every journal block.

pub const JBD2_MAGIC: u32 = 0xC03B_3998;

/// Block-type discriminant per `linux/jbd2.h`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlockType {
    Descriptor   = 1,
    Commit       = 2,
    SuperblockV1 = 3,
    SuperblockV2 = 4,
    Revoke       = 5,
}

impl BlockType {
    #[inline]
    /// # C: O(1)
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(BlockType::Descriptor),
            2 => Some(BlockType::Commit),
            3 => Some(BlockType::SuperblockV1),
            4 => Some(BlockType::SuperblockV2),
            5 => Some(BlockType::Revoke),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    pub block_type: BlockType,
    pub sequence:   u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HeaderError {
    Short,
    BadMagic,
    BadType,
}

impl BlockHeader {
    /// Parse a 12-byte JBD2 header from the start of `buf`.
    /// `Short` if `buf.len() < 12`; `BadMagic` if the magic word
    /// doesn't match; `BadType` for out-of-range block_type.
    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Result<Self, HeaderError> {
        if buf.len() < 12 { return Err(HeaderError::Short); }
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != JBD2_MAGIC { return Err(HeaderError::BadMagic); }
        let blocktype_raw = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let block_type = BlockType::from_u32(blocktype_raw).ok_or(HeaderError::BadType)?;
        let sequence = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        Ok(BlockHeader { block_type, sequence })
    }

    /// Write a 12-byte header into the start of `buf`. Panics if
    /// `buf.len() < 12`.
    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&(self.block_type as u32).to_be_bytes());
        buf[8..12].copy_from_slice(&self.sequence.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut b = [0u8; 12];
        let h0 = BlockHeader { block_type: BlockType::Descriptor, sequence: 42 };
        h0.write_to(&mut b);
        let h1 = BlockHeader::parse(&b).unwrap();
        assert_eq!(h0, h1);
    }

    #[test]
    fn rejects_bad_magic() {
        let b = [0u8; 16];
        assert_eq!(BlockHeader::parse(&b).err().unwrap(), HeaderError::BadMagic);
    }

    #[test]
    fn rejects_short() {
        let b = [0u8; 8];
        assert_eq!(BlockHeader::parse(&b).err().unwrap(), HeaderError::Short);
    }

    #[test]
    fn rejects_bad_type() {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        b[4..8].copy_from_slice(&99u32.to_be_bytes());
        assert_eq!(BlockHeader::parse(&b).err().unwrap(), HeaderError::BadType);
    }
}
