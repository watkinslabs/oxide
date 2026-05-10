// Journal superblock: block 0 of the journal device. Two
// versions (v1 = 1024 bytes, v2 = 1024 bytes with feature words);
// we read the fields that matter for replay.
//
// All multi-byte fields are big-endian per JBD2 convention.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct JournalSuperblock {
    /// Block size of the journal device in bytes.
    pub block_size:    u32,
    /// Total number of journal blocks (incl. superblock).
    pub maxlen:        u32,
    /// First block index that holds log data (skip header + revoke
    /// reserved area). Set to 1 by default.
    pub first:         u32,
    /// Sequence number of the first transaction expected on log.
    pub sequence:      u32,
    /// Block index of the first transaction's descriptor.
    pub start:         u32,
    pub feature_compat:   u32,
    pub feature_incompat: u32,
    pub feature_ro:    u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum JournalSuperblockError {
    Short,
    BadMagic,
    BadType,
}

impl JournalSuperblock {
    /// Parse the journal superblock from `buf` (≥ 1024 bytes).
    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Result<Self, JournalSuperblockError> {
        if buf.len() < 0x100 { return Err(JournalSuperblockError::Short); }
        // Header at offset 0..12.
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != crate::JBD2_MAGIC { return Err(JournalSuperblockError::BadMagic); }
        let bt = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if bt != 3 && bt != 4 { return Err(JournalSuperblockError::BadType); }
        // Body at offset 12 onward.
        Ok(JournalSuperblock {
            block_size:       u32::from_be_bytes([buf[0x0C], buf[0x0D], buf[0x0E], buf[0x0F]]),
            maxlen:           u32::from_be_bytes([buf[0x10], buf[0x11], buf[0x12], buf[0x13]]),
            first:            u32::from_be_bytes([buf[0x14], buf[0x15], buf[0x16], buf[0x17]]),
            sequence:         u32::from_be_bytes([buf[0x18], buf[0x19], buf[0x1A], buf[0x1B]]),
            start:            u32::from_be_bytes([buf[0x1C], buf[0x1D], buf[0x1E], buf[0x1F]]),
            feature_compat:   if bt == 4 { u32::from_be_bytes([buf[0x24], buf[0x25], buf[0x26], buf[0x27]]) } else { 0 },
            feature_incompat: if bt == 4 { u32::from_be_bytes([buf[0x28], buf[0x29], buf[0x2A], buf[0x2B]]) } else { 0 },
            feature_ro:       if bt == 4 { u32::from_be_bytes([buf[0x2C], buf[0x2D], buf[0x2E], buf[0x2F]]) } else { 0 },
        })
    }

    /// Returns `true` iff the journal needs replay (start != 0).
    /// Per linux/jbd2: `s_start = 0` means "log is clean".
    /// # C: O(1)
    pub fn needs_recovery(&self) -> bool { self.start != 0 }
}

/// JBD2 INCOMPAT feature bits per `linux/jbd2.h`.
pub const JBD2_INCOMPAT_REVOKE:    u32 = 0x0001;
pub const JBD2_INCOMPAT_64BIT:     u32 = 0x0002;
pub const JBD2_INCOMPAT_ASYNC_COMMIT: u32 = 0x0004;
pub const JBD2_INCOMPAT_CSUM_V2:   u32 = 0x0008;
pub const JBD2_INCOMPAT_CSUM_V3:   u32 = 0x0010;

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sb(block_size: u32, maxlen: u32, first: u32, seq: u32, start: u32) -> std::vec::Vec<u8> {
        let mut v = std::vec![0u8; 1024];
        v[0..4].copy_from_slice(&crate::JBD2_MAGIC.to_be_bytes());
        v[4..8].copy_from_slice(&3u32.to_be_bytes());  // v1 type
        v[0x0C..0x10].copy_from_slice(&block_size.to_be_bytes());
        v[0x10..0x14].copy_from_slice(&maxlen.to_be_bytes());
        v[0x14..0x18].copy_from_slice(&first.to_be_bytes());
        v[0x18..0x1C].copy_from_slice(&seq.to_be_bytes());
        v[0x1C..0x20].copy_from_slice(&start.to_be_bytes());
        v
    }

    #[test]
    fn parse_v1() {
        let b = build_sb(1024, 1024, 1, 1, 0);
        let sb = JournalSuperblock::parse(&b).unwrap();
        assert_eq!(sb.block_size, 1024);
        assert_eq!(sb.maxlen, 1024);
        assert_eq!(sb.start, 0);
        assert!(!sb.needs_recovery());
    }

    #[test]
    fn parse_needs_recovery() {
        let b = build_sb(4096, 8192, 1, 5, 100);
        let sb = JournalSuperblock::parse(&b).unwrap();
        assert!(sb.needs_recovery());
        assert_eq!(sb.start, 100);
    }

    #[test]
    fn rejects_bad_magic() {
        let b = std::vec![0u8; 1024];
        assert_eq!(JournalSuperblock::parse(&b), Err(JournalSuperblockError::BadMagic));
    }
}
