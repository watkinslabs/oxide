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
