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
    /// Journal UUID carried by the first tag of every descriptor block.
    pub uuid:          [u8; 16],
    /// `s_checksum_type`; crc32c (4) is required by checksum v2/v3.
    pub checksum_type: u8,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum JournalSuperblockError {
    Short,
    BadMagic,
    BadType,
    BadFeatures,
    BadChecksumType,
    BadChecksum,
}

impl JournalSuperblock {
    /// Parse the journal superblock from `buf` (≥ 1024 bytes).
    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Result<Self, JournalSuperblockError> {
        if buf.len() < 0x100 { return Err(JournalSuperblockError::Short); }
        // Header at offset 0..12.
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != super::JBD2_MAGIC { return Err(JournalSuperblockError::BadMagic); }
        let bt = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if bt != 3 && bt != 4 { return Err(JournalSuperblockError::BadType); }
        // Body at offset 12 onward.
        let mut uuid = [0u8; 16];
        if bt == 4 { uuid.copy_from_slice(&buf[0x30..0x40]); }
        let feature_compat = if bt == 4 { u32::from_be_bytes([buf[0x24], buf[0x25], buf[0x26], buf[0x27]]) } else { 0 };
        let feature_incompat = if bt == 4 { u32::from_be_bytes([buf[0x28], buf[0x29], buf[0x2A], buf[0x2B]]) } else { 0 };
        let checksum_type = if bt == 4 { buf[0x50] } else { 0 };
        let v1 = feature_compat & JBD2_COMPAT_CHECKSUM != 0;
        let v2 = feature_incompat & JBD2_INCOMPAT_CSUM_V2 != 0;
        let v3 = feature_incompat & JBD2_INCOMPAT_CSUM_V3 != 0;
        if (v2 && v3) || (v1 && (v2 || v3)) {
            return Err(JournalSuperblockError::BadFeatures);
        }
        if v2 || v3 {
            if checksum_type != super::checksum::JBD2_CRC32C_CHKSUM {
                return Err(JournalSuperblockError::BadChecksumType);
            }
            if buf.len() < super::checksum::SUPERBLOCK_BYTES {
                return Err(JournalSuperblockError::Short);
            }
            if !super::checksum::verify_zeroed_word(
                0xFFFF_FFFF,
                &buf[..super::checksum::SUPERBLOCK_BYTES],
                super::checksum::SUPERBLOCK_CHECKSUM_OFFSET,
            ) {
                return Err(JournalSuperblockError::BadChecksum);
            }
        }
        Ok(JournalSuperblock {
            block_size:       u32::from_be_bytes([buf[0x0C], buf[0x0D], buf[0x0E], buf[0x0F]]),
            maxlen:           u32::from_be_bytes([buf[0x10], buf[0x11], buf[0x12], buf[0x13]]),
            first:            u32::from_be_bytes([buf[0x14], buf[0x15], buf[0x16], buf[0x17]]),
            sequence:         u32::from_be_bytes([buf[0x18], buf[0x19], buf[0x1A], buf[0x1B]]),
            start:            u32::from_be_bytes([buf[0x1C], buf[0x1D], buf[0x1E], buf[0x1F]]),
            feature_compat,
            feature_incompat,
            feature_ro:       if bt == 4 { u32::from_be_bytes([buf[0x2C], buf[0x2D], buf[0x2E], buf[0x2F]]) } else { 0 },
            uuid,
            checksum_type,
        })
    }

    /// Returns `true` iff the journal needs replay (start != 0).
    /// Per linux/jbd2: `s_start = 0` means "log is clean".
    /// # C: O(1)
    pub fn needs_recovery(&self) -> bool { self.start != 0 }

    /// Validated checksum layout advertised by this journal.
    /// # C: O(1)
    pub fn checksum_mode(&self) -> super::checksum::ChecksumMode {
        if self.feature_incompat & JBD2_INCOMPAT_CSUM_V3 != 0 {
            super::checksum::ChecksumMode::V3
        } else if self.feature_incompat & JBD2_INCOMPAT_CSUM_V2 != 0 {
            super::checksum::ChecksumMode::V2
        } else if self.feature_compat & JBD2_COMPAT_CHECKSUM != 0 {
            super::checksum::ChecksumMode::V1
        } else {
            super::checksum::ChecksumMode::None
        }
    }

    /// Re-stamp the 1024-byte journal superblock checksum after changing a
    /// dynamic field. No-op for unchecksummed/checksum-v1 journals.
    /// # C: O(1024)
    pub fn stamp_checksum(&self, buf: &mut [u8]) -> bool {
        if !self.checksum_mode().has_block_checksums() { return true; }
        if buf.len() < super::checksum::SUPERBLOCK_BYTES { return false; }
        super::checksum::stamp_zeroed_word(
            0xFFFF_FFFF,
            &mut buf[..super::checksum::SUPERBLOCK_BYTES],
            super::checksum::SUPERBLOCK_CHECKSUM_OFFSET,
        )
    }
}

/// JBD2 COMPAT feature bits per `linux/jbd2.h`.
pub const JBD2_COMPAT_CHECKSUM: u32 = 0x0001;

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
        v[0..4].copy_from_slice(&super::super::JBD2_MAGIC.to_be_bytes());
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
    fn parse_v2_retains_descriptor_uuid() {
        let uuid = [0x5Au8; 16];
        let mut b = build_sb(4096, 8192, 1, 5, 100);
        b[4..8].copy_from_slice(&4u32.to_be_bytes());
        b[0x30..0x40].copy_from_slice(&uuid);
        let sb = JournalSuperblock::parse(&b).unwrap();
        assert_eq!(sb.uuid, uuid);
    }

    #[test]
    fn parse_checksum_v3_verifies_superblock() {
        let mut b = build_sb(4096, 8192, 1, 5, 100);
        b[4..8].copy_from_slice(&4u32.to_be_bytes());
        b[0x28..0x2C].copy_from_slice(&JBD2_INCOMPAT_CSUM_V3.to_be_bytes());
        b[0x50] = super::super::checksum::JBD2_CRC32C_CHKSUM;
        assert!(super::super::checksum::stamp_zeroed_word(
            0xFFFF_FFFF, &mut b, super::super::checksum::SUPERBLOCK_CHECKSUM_OFFSET));
        let sb = JournalSuperblock::parse(&b).unwrap();
        assert_eq!(sb.checksum_mode(), super::super::checksum::ChecksumMode::V3);
        b[0x60] ^= 1;
        assert_eq!(JournalSuperblock::parse(&b), Err(JournalSuperblockError::BadChecksum));
    }

    #[test]
    fn rejects_bad_magic() {
        let b = std::vec![0u8; 1024];
        assert_eq!(JournalSuperblock::parse(&b), Err(JournalSuperblockError::BadMagic));
    }
}
