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
pub const INCOMPAT_FLEX_BG:  u32 = 0x0200;
/// `s_feature_incompat` CSUM_SEED — `s_checksum_seed` overrides the UUID seed.
pub const INCOMPAT_CSUM_SEED: u32 = 0x2000;
/// `s_feature_compat` HAS_JOURNAL bit.
pub const COMPAT_HAS_JOURNAL: u32 = 0x0004;
/// `s_feature_ro_compat` METADATA_CSUM bit.
pub const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
pub const RO_COMPAT_GDT_CSUM:      u32 = 0x0010;
pub const RO_COMPAT_SPARSE_SUPER:  u32 = 0x0001;
pub const RO_COMPAT_LARGE_FILE:    u32 = 0x0002;
pub const RO_COMPAT_HUGE_FILE:     u32 = 0x0008;
pub const RO_COMPAT_DIR_NLINK:     u32 = 0x0020;
pub const RO_COMPAT_EXTRA_ISIZE:   u32 = 0x0040;
pub const RO_COMPAT_QUOTA:         u32 = 0x0100;
pub const RO_COMPAT_PROJECT:       u32 = 0x2000;

/// INCOMPAT features this driver understands well enough to interpret the
/// on-disk layout. An INCOMPAT bit OUTSIDE this set (e.g. META_BG, MMP, INLINE_
/// DATA, ENCRYPT, CASEFOLD, LARGEDIR, EA_INODE) means the layout would be
/// misread → refuse the mount (Linux `EXT4_FEATURE_INCOMPAT_SUPP`).
pub const SUPPORTED_INCOMPAT: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_RECOVER | INCOMPAT_EXTENTS | INCOMPAT_64BIT
    | INCOMPAT_FLEX_BG | INCOMPAT_CSUM_SEED;

/// RO_COMPAT features this driver can safely WRITE. A bit outside this set
/// (notably BIGALLOC=0x200, whose cluster bitmap we'd misread as per-block, or
/// VERITY) means the fs must not be written by us (Linux
/// `EXT4_FEATURE_RO_COMPAT_SUPP` → RO mount). We have no RO-mount path yet, so
/// an unknown RO_COMPAT bit refuses the mount rather than risk write corruption.
pub const SUPPORTED_RO_COMPAT: u32 =
    RO_COMPAT_METADATA_CSUM | RO_COMPAT_GDT_CSUM | RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE | RO_COMPAT_HUGE_FILE | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE | RO_COMPAT_QUOTA | RO_COMPAT_PROJECT
    | RO_COMPAT_METADATA_CSUM_SEED;

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
/// `s_volume_name` byte offset in the superblock; fixed 16-byte ext4 label.
pub const SB_OFF_VOLUME_NAME:    usize = 0x78;
/// `EXT4_LABEL_MAX`: on-disk label bytes, not necessarily NUL-terminated.
pub const EXT4_LABEL_MAX:        usize = 16;
/// Hidden quota inode fields (`s_*_quota_inum`) per Linux `ext4_super_block`.
pub const SB_OFF_USR_QUOTA_INUM: usize = 0x240;
pub const SB_OFF_GRP_QUOTA_INUM: usize = 0x244;
pub const SB_OFF_PRJ_QUOTA_INUM: usize = 0x26C;
/// `s_checksum_seed` byte offset (when METADATA_CSUM_SEED feature on).
pub const SB_OFF_CHECKSUM_SEED:  usize = 0x270;
/// `s_reserved_gdt_blocks` byte offset.
pub const SB_OFF_RESERVED_GDT_BLOCKS: usize = 0xCE;
/// `s_feature_ro_compat` METADATA_CSUM_SEED bit.
pub const RO_COMPAT_METADATA_CSUM_SEED: u32 = 0x0020_0000;

/// Parsed ext4 superblock fields used by both read + write paths.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Superblock {
    pub inodes_count:    u32,
    pub blocks_count_lo: u32,
    /// `s_blocks_count_hi` (0x150) — high 32 bits of the total block count on a
    /// 64bit fs (0 otherwise). Merged with `_lo` by [`Superblock::blocks_count`]
    /// so >2³²-block (>16 TiB) filesystems are not truncated.
    pub blocks_count_hi: u32,
    /// `s_r_blocks_count` (lo@0x08 + hi@0x154) — blocks reserved for the
    /// super-user. `statfs(2)` reports `f_bavail = f_bfree - r_blocks_count`
    /// (Linux `ext4_statfs`), so an unprivileged writer sees the space it may
    /// actually consume rather than the root-only reserve.
    pub r_blocks_count: u64,
    /// `s_first_ino` (0x54) — first non-reserved inode (11 on stock ext4). Drives
    /// where inode allocation may begin; read instead of hardcoded.
    pub first_ino: u32,
    /// `s_desc_size` (0xFE) — on-disk group-descriptor size for a 64bit fs (>=64,
    /// may exceed 64 on future layouts); 32 without 64bit. Read instead of derived.
    pub desc_size: u16,
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
    /// `s_volume_name[16]` — ext4 filesystem label, zero-padded on disk.
    pub volume_name: [u8; EXT4_LABEL_MAX],
    /// Hidden quota file inode numbers. Linux treats these as quota files and
    /// rejects user flag/project-id mutation.
    pub usr_quota_inum: u32,
    pub grp_quota_inum: u32,
    pub prj_quota_inum: u32,
    /// Stored-seed override (when RO_COMPAT_METADATA_CSUM_SEED on).
    /// Otherwise zero; caller derives from `uuid` instead.
    pub stored_csum_seed: u32,
    /// `s_hash_seed[4]` (htree directory hash seed). Read as 4 le32
    /// words from offset 0xEC. All-zero ⇒ use the built-in default.
    pub hash_seed: [u32; 4],
    /// `s_def_hash_version` (offset 0xFC) — default htree hash algo.
    pub def_hash_version: u8,
    /// `s_reserved_gdt_blocks`: resize_inode-reserved GDT blocks after each
    /// primary/backup descriptor table.
    pub reserved_gdt_blocks: u16,
}

/// Field offsets we mutate when persisting counter updates back to
/// the on-disk superblock. Exposed for `mount`'s writeback path.
pub const SB_OFF_FREE_BLOCKS_LO: usize = 0x0C;
pub const SB_OFF_FREE_INODES:    usize = 0x10;
/// `s_r_blocks_count_lo` (__le32 @0x08) — blocks reserved for the super-user.
/// `statfs` subtracts these from `f_bfree` to get `f_bavail`.
pub const SB_OFF_R_BLOCKS_LO:    usize = 0x08;
// The 64bit-feature high halves are three CONSECUTIVE __le32 at 0x150/0x154/
// 0x158 in `struct ext4_super_block`: s_blocks_count_hi, s_r_blocks_count_hi,
// s_free_blocks_count_hi — in that order.
pub const SB_OFF_BLOCKS_HI:      usize = 0x150;
pub const SB_OFF_R_BLOCKS_HI:    usize = 0x154;
pub const SB_OFF_FREE_BLOCKS_HI: usize = 0x158;
/// `EXT4_NAME_LEN` — longest directory-entry name, reported as statfs `f_namelen`.
pub const EXT4_NAME_LEN: u64 = 255;

/// Linux `uuid_to_fsid` (include/linux/statfs.h): fold the 16-byte on-disk
/// `s_uuid` to the 64-bit `statfs` `f_fsid` by XOR-ing its two little-endian
/// halves. The result is stable across mounts, unlike `s_dev`. # C: O(1)
pub fn uuid_to_fsid(uuid: &[u8; 16]) -> u64 {
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&uuid[..8]);
    hi.copy_from_slice(&uuid[8..]);
    u64::from_le_bytes(lo) ^ u64::from_le_bytes(hi)
}
/// `s_last_orphan` (__le32 @0xE8): head of the on-disk orphan-inode list —
/// the most recently orphaned inode (deleted-but-open / O_TMPFILE awaiting a
/// name). Each listed inode chains to the previous head via its `i_dtime`
/// field (`NEXT_ORPHAN`). Linux `ext4_orphan_add`/`_del`/`_cleanup`.
pub const SB_OFF_LAST_ORPHAN:    usize = 0xE8;
/// `s_mtime` (__le32 @0x2C): last-mount wall-clock (secs since epoch).
pub const SB_OFF_MTIME:          usize = 0x2C;
/// `s_wtime` (__le32 @0x30): last-write (superblock touch) wall-clock (secs).
pub const SB_OFF_WTIME:          usize = 0x30;
/// `s_mnt_count` (__le16 @0x34): mounts since last fsck.
pub const SB_OFF_MNT_COUNT:      usize = 0x34;
/// `s_state` (__le16 @0x3A): filesystem state bitmask.
pub const SB_OFF_STATE:          usize = 0x3A;

/// `s_state` EXT4_VALID_FS — set when the fs was cleanly unmounted. A rw mount
/// clears it (Linux `ext4_setup_super`); a clean unmount restores it. e2fsck
/// forces a check when it is clear.
pub const EXT4_VALID_FS: u16 = 0x0001;
/// `s_state` EXT4_ERROR_FS — set by the kernel on a detected fs error. Left
/// untouched by the mount-lifecycle writeback.
pub const EXT4_ERROR_FS: u16 = 0x0002;

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
        let is_64bit = (rd_u32(buf, 0x60) & INCOMPAT_64BIT) != 0;
        let first_ino = { let v = rd_u32(buf, 0x54); if v < 11 { 11 } else { v } };
        let desc_size = if is_64bit { let d = rd_u16(buf, 0xFE); if d < 64 { 64 } else { d } } else { 32 };
        Ok(Superblock {
            inodes_count:      rd_u32(buf, 0x00),
            blocks_count_lo:   rd_u32(buf, 0x04),
            blocks_count_hi:   if is_64bit { rd_u32(buf, SB_OFF_BLOCKS_HI) } else { 0 },
            r_blocks_count:    (rd_u32(buf, SB_OFF_R_BLOCKS_LO) as u64)
                | if is_64bit { (rd_u32(buf, SB_OFF_R_BLOCKS_HI) as u64) << 32 } else { 0 },
            first_ino,
            desc_size,
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
            volume_name:       {
                let mut v = [0u8; EXT4_LABEL_MAX];
                v.copy_from_slice(&buf[SB_OFF_VOLUME_NAME..SB_OFF_VOLUME_NAME + EXT4_LABEL_MAX]);
                v
            },
            usr_quota_inum:    rd_u32(buf, SB_OFF_USR_QUOTA_INUM),
            grp_quota_inum:    rd_u32(buf, SB_OFF_GRP_QUOTA_INUM),
            prj_quota_inum:    rd_u32(buf, SB_OFF_PRJ_QUOTA_INUM),
            stored_csum_seed:  rd_u32(buf, SB_OFF_CHECKSUM_SEED),
            hash_seed: [
                rd_u32(buf, 0xEC), rd_u32(buf, 0xF0),
                rd_u32(buf, 0xF4), rd_u32(buf, 0xF8),
            ],
            def_hash_version: buf[0xFC],
            reserved_gdt_blocks: rd_u16(buf, SB_OFF_RESERVED_GDT_BLOCKS),
        })
    }

    /// True iff this fs uses ext4 extents (vs ext2/3 indirect blocks).
    /// # C: O(1)
    pub fn has_extents(&self) -> bool {
        (self.feature_incompat & INCOMPAT_EXTENTS) != 0
    }

    /// Number of block groups, derived from blocks_count + blocks_per_group.
    /// # C: O(1)
    /// Total block count, merging `s_blocks_count_hi` (64bit fs). # C: O(1)
    pub fn blocks_count(&self) -> u64 {
        (self.blocks_count_lo as u64) | ((self.blocks_count_hi as u64) << 32)
    }

    pub fn group_count(&self) -> u32 {
        if self.blocks_per_group == 0 { return 0; }
        let total = self.blocks_count();
        ((total + self.blocks_per_group as u64 - 1) / self.blocks_per_group as u64) as u32
    }

    /// True iff the FS was built with metadata_csum.
    /// # C: O(1)
    pub fn has_metadata_csum(&self) -> bool {
        (self.feature_ro_compat & RO_COMPAT_METADATA_CSUM) != 0
    }

    /// True iff sparse-super backup layout is enabled. # C: O(1)
    pub fn has_sparse_super(&self) -> bool {
        (self.feature_ro_compat & RO_COMPAT_SPARSE_SUPER) != 0
    }

    /// `EXT4_FEATURE_RO_COMPAT_HUGE_FILE`: when set, `i_blocks` uses the 48-bit
    /// (`i_blocks_lo` + `l_i_blocks_high`) form and a per-inode `EXT4_HUGE_FILE_FL`
    /// may switch its unit from 512-byte sectors to fs-blocks. When CLEAR,
    /// `i_blocks` is 32-bit `i_blocks_lo` only and `0x74` is `l_i_reserved` (must
    /// NOT be merged in as high bits). # C: O(1)
    pub fn has_huge_file(&self) -> bool {
        (self.feature_ro_compat & RO_COMPAT_HUGE_FILE) != 0
    }

    /// `EXT4_FEATURE_RO_COMPAT_PROJECT`: project-id quota/inheritance field is
    /// meaningful on this fs. # C: O(1)
    pub fn has_project(&self) -> bool {
        (self.feature_ro_compat & RO_COMPAT_PROJECT) != 0
    }

    /// `EXT4_FEATURE_RO_COMPAT_QUOTA`: hidden quota files are kernel-owned and
    /// enabled at read-write mount time. # C: O(1)
    pub fn has_quota(&self) -> bool {
        (self.feature_ro_compat & RO_COMPAT_QUOTA) != 0
    }

    /// Linux hidden quota-file identity from `s_usr_quota_inum`,
    /// `s_grp_quota_inum`, and `s_prj_quota_inum`. # C: O(1)
    pub fn is_quota_inode(&self, ino: u32) -> bool {
        ino != 0 && (ino == self.usr_quota_inum || ino == self.grp_quota_inum || ino == self.prj_quota_inum)
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
    fn parses_hidden_quota_inode_numbers() {
        let mut b = make_sb(
            1024, 8192, 2,
            8192, 1024, EXT4_SUPER_MAGIC, INCOMPAT_EXTENTS, 256,
        );
        b[SB_OFF_USR_QUOTA_INUM..SB_OFF_USR_QUOTA_INUM + 4].copy_from_slice(&12u32.to_le_bytes());
        b[SB_OFF_GRP_QUOTA_INUM..SB_OFF_GRP_QUOTA_INUM + 4].copy_from_slice(&13u32.to_le_bytes());
        b[SB_OFF_PRJ_QUOTA_INUM..SB_OFF_PRJ_QUOTA_INUM + 4].copy_from_slice(&14u32.to_le_bytes());
        let sb = Superblock::parse(&b).expect("parse");
        assert_eq!(sb.usr_quota_inum, 12);
        assert_eq!(sb.grp_quota_inum, 13);
        assert_eq!(sb.prj_quota_inum, 14);
        assert!(sb.is_quota_inode(12));
        assert!(sb.is_quota_inode(13));
        assert!(sb.is_quota_inode(14));
        assert!(!sb.is_quota_inode(0));
        assert!(!sb.is_quota_inode(15));
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

    /// The three 64bit-feature high halves are CONSECUTIVE __le32 at
    /// 0x150/0x154/0x158 in declaration order: s_blocks_count_hi,
    /// s_r_blocks_count_hi, s_free_blocks_count_hi. Swapping the blocks and
    /// free-blocks offsets is silent on a small filesystem (both halves are 0)
    /// and corrupts a >16 TiB one on the counter-writeback path.
    #[test]
    fn the_64bit_high_half_offsets_are_in_ext4_declaration_order() {
        assert_eq!(SB_OFF_BLOCKS_HI, 0x150);
        assert_eq!(SB_OFF_R_BLOCKS_HI, 0x154);
        assert_eq!(SB_OFF_FREE_BLOCKS_HI, 0x158);
        assert_eq!(SB_OFF_R_BLOCKS_LO, 0x08);
        assert_eq!(SB_OFF_FREE_BLOCKS_LO, 0x0C);
    }

    #[test]
    fn a_64bit_fs_merges_each_high_half_into_its_own_counter() {
        let mut b = make_sb(1024, 0x1111_1111, 2, 8192, 1024, EXT4_SUPER_MAGIC,
                            INCOMPAT_EXTENTS | INCOMPAT_64BIT, 256);
        b[0x08..0x0C].copy_from_slice(&0x2222_2222u32.to_le_bytes());   // s_r_blocks_count_lo
        b[0x0C..0x10].copy_from_slice(&0x3333_3333u32.to_le_bytes());   // s_free_blocks_count_lo
        b[0x150..0x154].copy_from_slice(&0xAAu32.to_le_bytes());        // s_blocks_count_hi
        b[0x154..0x158].copy_from_slice(&0xBBu32.to_le_bytes());        // s_r_blocks_count_hi
        b[0x158..0x15C].copy_from_slice(&0xCCu32.to_le_bytes());        // s_free_blocks_count_hi
        let sb = Superblock::parse(&b).expect("parse");
        assert_eq!(sb.blocks_count(),    0x0000_00AA_1111_1111);
        assert_eq!(sb.r_blocks_count,    0x0000_00BB_2222_2222);
        assert_eq!(sb.free_blocks_count, 0x0000_00CC_3333_3333);
    }

    /// Without INCOMPAT_64BIT the high halves are reserved and must be ignored,
    /// even when the on-disk bytes are non-zero.
    #[test]
    fn a_32bit_fs_ignores_the_high_halves() {
        let mut b = make_sb(1024, 8192, 2, 8192, 1024, EXT4_SUPER_MAGIC, 0, 256);
        b[0x08..0x0C].copy_from_slice(&512u32.to_le_bytes());
        b[0x150..0x15C].copy_from_slice(&[0xffu8; 12]);
        let sb = Superblock::parse(&b).expect("parse");
        assert_eq!(sb.blocks_count(), 8192);
        assert_eq!(sb.r_blocks_count, 512, "the low half is still read");
    }

    /// Linux `uuid_to_fsid`: XOR the two little-endian halves of `s_uuid`.
    /// statfs reports THIS as `f_fsid`, not the ephemeral `s_dev`.
    #[test]
    fn fsid_folds_the_uuid_the_way_linux_does() {
        let mut u = [0u8; 16];
        u[..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        u[8..].copy_from_slice(&0x1112_1314_1516_1718u64.to_le_bytes());
        assert_eq!(uuid_to_fsid(&u), 0x0102_0304_0506_0708 ^ 0x1112_1314_1516_1718);
        // An all-zero UUID folds to 0, and identical halves cancel — both are
        // the Linux answer, not a special case.
        assert_eq!(uuid_to_fsid(&[0u8; 16]), 0);
        let mut same = [0u8; 16];
        same[..8].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        same[8..].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        assert_eq!(uuid_to_fsid(&same), 0);
    }

    #[test]
    fn ext4_name_len_is_255() {
        assert_eq!(EXT4_NAME_LEN, 255);
    }

    #[test]
    fn the_uuid_is_parsed_from_its_on_disk_offset() {
        let mut b = make_sb(1024, 8192, 2, 8192, 1024, EXT4_SUPER_MAGIC, 0, 256);
        let want: [u8; 16] = core::array::from_fn(|i| (i as u8) + 1);
        b[SB_OFF_UUID..SB_OFF_UUID + 16].copy_from_slice(&want);
        let sb = Superblock::parse(&b).expect("parse");
        assert_eq!(sb.uuid, want);
        assert_ne!(uuid_to_fsid(&sb.uuid), 0);
    }
}
