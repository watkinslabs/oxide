// ext4 superblock per Linux fs/ext4/ext4.h `ext4_super_block`.
// Located at byte offset 1024 from start of the partition; 1024
// bytes total. Pure parser — caller hands a 1024-byte slice.

/// `s_magic` constant per `ext4.h`.
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;

/// Superblock byte offset within the partition (per spec).
pub const SUPERBLOCK_OFFSET: u64 = 1024;

/// Superblock byte length.
pub const SUPERBLOCK_LEN: usize = 1024;

/// `s_feature_incompat` bits per `ext4.h`.
pub const INCOMPAT_FILETYPE: u32 = 0x0002;
pub const INCOMPAT_RECOVER:  u32 = 0x0004;
pub const INCOMPAT_EXTENTS:  u32 = 0x0040;
pub const INCOMPAT_64BIT:    u32 = 0x0080;
/// `s_feature_compat` HAS_JOURNAL bit.
pub const COMPAT_HAS_JOURNAL: u32 = 0x0004;
/// `s_feature_ro_compat` METADATA_CSUM bit.
pub const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
pub const RO_COMPAT_GDT_CSUM:      u32 = 0x0010;

/// Errors decoded from `parse`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SuperblockError {
    /// Slice was not 1024 bytes.
    BadLen,
    /// `s_magic` did not match `EXT4_SUPER_MAGIC`.
    BadMagic,
    /// `s_log_block_size` produced a block size out of range.
    BadBlockSize,
    /// `s_inode_size` was outside [128, block_size].
    BadInodeSize,
}

/// `s_uuid` byte offset in the superblock.
pub const SB_OFF_UUID:           usize = 0x68;
/// `s_checksum_seed` byte offset (when METADATA_CSUM_SEED feature on).
pub const SB_OFF_CHECKSUM_SEED:  usize = 0x270;
/// `s_feature_ro_compat` METADATA_CSUM_SEED bit.
pub const RO_COMPAT_METADATA_CSUM_SEED: u32 = 0x0020_0000;

/// Parsed ext4 superblock fields used by both read + write paths.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Superblock {
    pub inodes_count:    u32,
    pub blocks_count_lo: u32,
    /// Filesystem block size in bytes. Computed from
    /// `1024 << s_log_block_size`.
    pub block_size:      u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic:           u16,
    pub feature_compat:   u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub inode_size:      u16,
    /// `s_first_data_block`. 1 for 1 KiB-block FS (block 0 = boot
    /// sector pad), 0 otherwise. Drives group→physical-block math.
    pub first_data_block: u32,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    /// Inode of journal file (`s_journal_inum`). 0 ⇒ no journal.
    pub journal_inum: u32,
    /// 16-byte filesystem UUID (`s_uuid`). Used as the seed for
    /// metadata_csum computation when METADATA_CSUM_SEED is off.
    pub uuid: [u8; 16],
    /// Stored-seed override (when RO_COMPAT_METADATA_CSUM_SEED on).
    /// Otherwise zero; caller derives from `uuid` instead.
    pub stored_csum_seed: u32,
}

/// Field offsets we mutate when persisting counter updates back to
/// the on-disk superblock. Exposed for `mount`'s writeback path.
pub const SB_OFF_FREE_BLOCKS_LO: usize = 0x0C;
pub const SB_OFF_FREE_INODES:    usize = 0x10;
pub const SB_OFF_FREE_BLOCKS_HI: usize = 0x150;

/// Read a little-endian u16 / u32 / u64 at offset `o`. Caller
/// must ensure `buf.len() >= o + N`.
#[inline] fn rd_u16(buf: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([buf[o], buf[o+1]])
}
#[inline] fn rd_u32(buf: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([buf[o], buf[o+1], buf[o+2], buf[o+3]])
}

impl Superblock {
    /// Parse a 1024-byte superblock slice. Validates magic,
    /// block-size range, and inode-size range.
    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Result<Self, SuperblockError> {
        if buf.len() != SUPERBLOCK_LEN {
            return Err(SuperblockError::BadLen);
        }
        let magic = rd_u16(buf, 0x38);
        if magic != EXT4_SUPER_MAGIC {
            return Err(SuperblockError::BadMagic);
        }
        let log_bs = rd_u32(buf, 0x18);
        // Linux supports log_bs in 0..=6 → block size 1KiB..64KiB.
        if log_bs > 6 {
            return Err(SuperblockError::BadBlockSize);
        }
        let block_size = 1024u32 << log_bs;
        let inode_size = rd_u16(buf, 0x58);
        // Pre-ext4 fs may set s_inode_size=0 meaning 128.
        let inode_size = if inode_size == 0 { 128 } else { inode_size };
        if inode_size < 128 || inode_size as u32 > block_size {
            return Err(SuperblockError::BadInodeSize);
        }
        let free_blocks_lo = rd_u32(buf, SB_OFF_FREE_BLOCKS_LO) as u64;
        let free_blocks_hi = rd_u32(buf, SB_OFF_FREE_BLOCKS_HI) as u64;
        Ok(Superblock {
            inodes_count:      rd_u32(buf, 0x00),
            blocks_count_lo:   rd_u32(buf, 0x04),
            block_size,
            blocks_per_group:  rd_u32(buf, 0x20),
            inodes_per_group:  rd_u32(buf, 0x28),
            magic,
            feature_compat:    rd_u32(buf, 0x5C),
            feature_incompat:  rd_u32(buf, 0x60),
            feature_ro_compat: rd_u32(buf, 0x64),
            inode_size,
            first_data_block:  rd_u32(buf, 0x14),
            free_blocks_count: free_blocks_lo | (free_blocks_hi << 32),
            free_inodes_count: rd_u32(buf, SB_OFF_FREE_INODES),
            journal_inum:      rd_u32(buf, 0xE0),
            uuid:              {
                let mut u = [0u8; 16];
                u.copy_from_slice(&buf[SB_OFF_UUID..SB_OFF_UUID + 16]);
                u
            },
            stored_csum_seed:  rd_u32(buf, SB_OFF_CHECKSUM_SEED),
        })
    }

    /// True iff this fs uses ext4 extents (vs ext2/3 indirect blocks).
    /// # C: O(1)
    pub fn has_extents(&self) -> bool {
        (self.feature_incompat & INCOMPAT_EXTENTS) != 0
    }

    /// Number of block groups, derived from blocks_count + blocks_per_group.
    /// # C: O(1)
    pub fn group_count(&self) -> u32 {
        if self.blocks_per_group == 0 { return 0; }
        (self.blocks_count_lo + self.blocks_per_group - 1) / self.blocks_per_group
    }

    /// True iff the FS was built with metadata_csum.
    /// # C: O(1)
    pub fn has_metadata_csum(&self) -> bool {
        (self.feature_ro_compat & RO_COMPAT_METADATA_CSUM) != 0
    }

    /// True iff GDT_CSUM (legacy CRC16) is on instead of CRC32C.
    /// # C: O(1)
    pub fn has_gdt_csum(&self) -> bool {
        (self.feature_ro_compat & RO_COMPAT_GDT_CSUM) != 0
    }

    /// Compute the CRC32C seed used for metadata_csum. When the
    /// METADATA_CSUM_SEED feature is on, we trust the stored
    /// `s_checksum_seed`. Otherwise: seed = crc32c(0xFFFFFFFF, uuid).
    /// # C: O(16)
    pub fn metadata_csum_seed(&self) -> u32 {
        if (self.feature_ro_compat & RO_COMPAT_METADATA_CSUM_SEED) != 0 {
            self.stored_csum_seed
        } else {
            crc::crc32c_update(0xFFFF_FFFF, &self.uuid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimum-viable 1024-byte ext4 superblock with the
    /// fields we read populated to known values. Bytes outside
    /// our windows stay zero.
    fn make_sb(
        inodes_count: u32, blocks_count: u32, log_block_size: u32,
        bpg: u32, ipg: u32, magic: u16, incompat: u32, inode_size: u16,
    ) -> [u8; SUPERBLOCK_LEN] {
        let mut b = [0u8; SUPERBLOCK_LEN];
        b[0x00..0x04].copy_from_slice(&inodes_count.to_le_bytes());
        b[0x04..0x08].copy_from_slice(&blocks_count.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&log_block_size.to_le_bytes());
        b[0x20..0x24].copy_from_slice(&bpg.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&ipg.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&magic.to_le_bytes());
        b[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        b[0x58..0x5A].copy_from_slice(&inode_size.to_le_bytes());
        b
    }

    #[test]
    fn parse_canonical_4k_ext4() {
        // 4 KiB blocks (log=2), magic ok, INCOMPAT_EXTENTS set,
        // inode_size 256.
        let b = make_sb(
            1024, 8192, 2,
            8192, 1024, EXT4_SUPER_MAGIC, INCOMPAT_EXTENTS, 256,
        );
        let sb = Superblock::parse(&b).expect("parse");
        assert_eq!(sb.magic,            EXT4_SUPER_MAGIC);
        assert_eq!(sb.block_size,       4096);
        assert_eq!(sb.inodes_count,     1024);
        assert_eq!(sb.blocks_count_lo,  8192);
        assert_eq!(sb.blocks_per_group, 8192);
        assert_eq!(sb.inodes_per_group, 1024);
        assert_eq!(sb.inode_size,       256);
        assert!(sb.has_extents());
        assert_eq!(sb.group_count(),    1);
    }

    #[test]
    fn rejects_bad_len() {
        let short = [0u8; 100];
        assert_eq!(Superblock::parse(&short), Err(SuperblockError::BadLen));
        let long = [0u8; SUPERBLOCK_LEN + 1];
        assert_eq!(Superblock::parse(&long), Err(SuperblockError::BadLen));
    }

    #[test]
    fn rejects_bad_magic() {
        let b = make_sb(0, 0, 0, 0, 0, 0xDEAD, 0, 128);
        assert_eq!(Superblock::parse(&b), Err(SuperblockError::BadMagic));
    }

    #[test]
    fn rejects_huge_log_block_size() {
        let b = make_sb(0, 0, 99, 0, 0, EXT4_SUPER_MAGIC, 0, 128);
        assert_eq!(Superblock::parse(&b), Err(SuperblockError::BadBlockSize));
    }

    #[test]
    fn s_inode_size_zero_means_128() {
        let b = make_sb(0, 0, 0, 0, 0, EXT4_SUPER_MAGIC, 0, 0);
        let sb = Superblock::parse(&b).expect("parse");
        assert_eq!(sb.inode_size, 128, "s_inode_size==0 → ext2-era 128");
    }

    #[test]
    fn rejects_inode_size_below_128() {
        let b = make_sb(0, 0, 0, 0, 0, EXT4_SUPER_MAGIC, 0, 64);
        assert_eq!(Superblock::parse(&b), Err(SuperblockError::BadInodeSize));
    }

    #[test]
    fn group_count_handles_partial_last_group() {
        // 8200 blocks, bpg=8192 → 2 groups.
        let b = make_sb(0, 8200, 2, 8192, 0, EXT4_SUPER_MAGIC, 0, 128);
        let sb = Superblock::parse(&b).expect("parse");
        assert_eq!(sb.group_count(), 2);
    }

    #[test]
    fn group_count_zero_bpg_safe() {
        let b = make_sb(0, 100, 0, 0, 0, EXT4_SUPER_MAGIC, 0, 128);
        let sb = Superblock::parse(&b).expect("parse");
        assert_eq!(sb.group_count(), 0);
    }

    #[test]
    fn ext4_extents_flag_pinned() {
        assert_eq!(INCOMPAT_EXTENTS, 0x0040);
    }

    #[test]
    fn magic_pinned() {
        assert_eq!(EXT4_SUPER_MAGIC, 0xEF53);
    }
}
