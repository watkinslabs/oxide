//! The on-disk numbers exFAT is defined in terms of.
//!
//! Every value here is fixed by the format, not by this implementation: an
//! entry is 32 bytes because the format says so, and cluster 2 is the first
//! of the heap because the two before it are reserved.

/// Last two bytes of the boot sector.
pub const BOOT_SIGNATURE: u16 = 0xAA55;
/// Last four bytes of each extended boot sector.
pub const EXBOOT_SIGNATURE: u32 = 0xAA55_0000;
/// The eight bytes that say a volume is exFAT rather than FAT.
pub const FS_NAME: &[u8; 8] = b"EXFAT   ";

/// Offsets into the boot sector.
pub const OFF_JMP_BOOT: usize = 0;
pub const OFF_FS_NAME: usize = 3;
pub const OFF_MUST_BE_ZERO: usize = 11;
pub const OFF_PARTITION_OFFSET: usize = 64;
pub const OFF_VOL_LENGTH: usize = 72;
pub const OFF_FAT_OFFSET: usize = 80;
pub const OFF_FAT_LENGTH: usize = 84;
pub const OFF_CLU_OFFSET: usize = 88;
pub const OFF_CLU_COUNT: usize = 92;
pub const OFF_ROOT_CLUSTER: usize = 96;
pub const OFF_VOL_SERIAL: usize = 100;
pub const OFF_FS_REVISION: usize = 104;
pub const OFF_VOL_FLAGS: usize = 106;
pub const OFF_SECT_SIZE_BITS: usize = 108;
pub const OFF_SECT_PER_CLUS_BITS: usize = 109;
pub const OFF_NUM_FATS: usize = 110;
pub const OFF_DRV_SEL: usize = 111;
pub const OFF_PERCENT_IN_USE: usize = 112;
pub const OFF_SIGNATURE: usize = 510;

/// Length of the field that must be zero to tell exFAT from FAT.
pub const MUST_BE_ZERO_LEN: usize = 53;
/// Length of the boot-sector name field.
pub const FS_NAME_LEN: usize = 8;
/// The first sector every volume has, whatever it declares.
pub const MIN_BOOT_BYTES: usize = 512;

/// Volume flags.
pub const VOLUME_DIRTY: u16 = 0x0002;
pub const MEDIA_FAILURE: u16 = 0x0004;
/// The two flags a mount must carry forward rather than clear.
pub const VOLUME_PERSISTENT_FLAGS: u16 = VOLUME_DIRTY | MEDIA_FAILURE;

/// Cluster values with a meaning of their own.
pub const EOF_CLUSTER: u32 = 0xFFFF_FFFF;
pub const BAD_CLUSTER: u32 = 0xFFFF_FFF7;
pub const FREE_CLUSTER: u32 = 0;
/// Clusters 0 and 1 are reserved; the heap starts at 2.
pub const RESERVED_CLUSTERS: u32 = 2;
pub const FIRST_CLUSTER: u32 = 2;
/// The largest cluster number the format admits.
pub const MAX_NUM_CLUSTER: u32 = 0xFFFF_FFF5;
/// Bytes of one FAT entry.
pub const FAT_ENTRY_BYTES: usize = 4;

/// Allocation flags in a secondary entry's `GeneralSecondaryFlags`.
pub const ALLOC_POSSIBLE: u8 = 0x01;
pub const ALLOC_FAT_CHAIN: u8 = 0x01;
pub const ALLOC_NO_FAT_CHAIN: u8 = 0x03;

/// One directory entry.
pub const DENTRY_BYTES: usize = 32;
pub const DENTRY_BITS: u32 = 5;
/// The largest directory the format admits, in entries.
pub const MAX_DENTRIES: u64 = 8_388_608;

/// Entry type bytes.
pub const TYPE_UNUSED: u8 = 0x00;
/// A used entry has the high bit set; clearing it deletes the entry.
pub const IN_USE_BIT: u8 = 0x80;
pub const TYPE_INVAL: u8 = 0x80;
pub const TYPE_BITMAP: u8 = 0x81;
pub const TYPE_UPCASE: u8 = 0x82;
pub const TYPE_VOLUME: u8 = 0x83;
pub const TYPE_FILE: u8 = 0x85;
pub const TYPE_GUID: u8 = 0xA0;
pub const TYPE_PADDING: u8 = 0xA1;
pub const TYPE_ACLTAB: u8 = 0xA2;
pub const TYPE_STREAM: u8 = 0xC0;
pub const TYPE_NAME: u8 = 0xC1;
pub const TYPE_ACL: u8 = 0xC2;
pub const TYPE_VENDOR_EXT: u8 = 0xE0;
pub const TYPE_VENDOR_ALLOC: u8 = 0xE1;

/// Class boundaries within the type byte.
pub const CRITICAL_PRI_MAX: u8 = 0xA0;
pub const BENIGN_PRI_MAX: u8 = 0xC0;
pub const CRITICAL_SEC_MAX: u8 = 0xE0;

/// File attributes.
pub const ATTR_READONLY: u16 = 0x0001;
pub const ATTR_HIDDEN: u16 = 0x0002;
pub const ATTR_SYSTEM: u16 = 0x0004;
pub const ATTR_VOLUME: u16 = 0x0008;
pub const ATTR_SUBDIR: u16 = 0x0010;
pub const ATTR_ARCHIVE: u16 = 0x0020;
/// The attributes a caller may set.
pub const ATTR_RWMASK: u16 = ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME | ATTR_SUBDIR | ATTR_ARCHIVE;

/// UTF-16 units one name entry carries.
pub const NAME_CHARS_PER_ENTRY: usize = 15;
/// UTF-16 units a volume label carries.
pub const VOLUME_LABEL_LEN: usize = 11;
/// Longest name the format admits, in UTF-16 units.
pub const MAX_NAME_LENGTH: usize = 255;

/// Index of each entry within a set.
pub const ES_IDX_FILE: usize = 0;
pub const ES_IDX_STREAM: usize = 1;
pub const ES_IDX_FIRST_NAME: usize = 2;

/// Sector-size bits the format admits.
pub const MIN_SECT_SIZE_BITS: u8 = 9;
pub const MAX_SECT_SIZE_BITS: u8 = 12;
/// A cluster may not exceed 32 MiB, which is what this bound expresses.
pub const MAX_CLUSTER_SIZE_BITS: u8 = 25;

/// `OffsetValid` in a timestamp's UTC-offset byte.
pub const TZ_VALID: u8 = 1 << 7;
/// The offset field is a count of quarter-hours.
pub const TZ_UNIT_MINUTES: i64 = 15;
/// Offsets above this are negative, in two's complement over seven bits.
pub const TZ_NEGATIVE_FROM: u8 = 0x40;
pub const TZ_MODULUS: u8 = 0x80;

/// Jan 1 1980 00:00:00 UTC, the earliest instant a timestamp can name.
pub const MIN_TIMESTAMP_SECS: i64 = 315_532_800;
/// Dec 31 2107 23:59:59 UTC, the latest.
pub const MAX_TIMESTAMP_SECS: i64 = 4_354_819_199;

/// The number the reference reports for a mounted exFAT volume.
pub const EXFAT_SUPER_MAGIC: u64 = 0x2011_BAB0;
/// The root directory's inode number.
pub const ROOT_INO: u64 = 1;

/// Offsets within a file entry.
pub const FILE_OFF_NUM_EXT: usize = 1;
pub const FILE_OFF_CHECKSUM: usize = 2;
pub const FILE_OFF_ATTR: usize = 4;
pub const FILE_OFF_CREATE_TIME: usize = 8;
pub const FILE_OFF_CREATE_DATE: usize = 10;
pub const FILE_OFF_MODIFY_TIME: usize = 12;
pub const FILE_OFF_MODIFY_DATE: usize = 14;
pub const FILE_OFF_ACCESS_TIME: usize = 16;
pub const FILE_OFF_ACCESS_DATE: usize = 18;
pub const FILE_OFF_CREATE_CS: usize = 20;
pub const FILE_OFF_MODIFY_CS: usize = 21;
pub const FILE_OFF_CREATE_TZ: usize = 22;
pub const FILE_OFF_MODIFY_TZ: usize = 23;
pub const FILE_OFF_ACCESS_TZ: usize = 24;

/// The two bytes of the file entry that carry the set's own checksum, and so
/// are skipped while computing it.
pub const CHECKSUM_SKIP: [usize; 2] = [2, 3];
/// The three boot-sector bytes excluded from the boot checksum: the volume
/// flags, which a mount changes, and the in-use percentage, which a write
/// changes.
pub const BOOT_CHECKSUM_SKIP: [usize; 3] = [106, 107, 112];
/// Sectors of the boot region covered by the checksum, before the checksum
/// sector itself.
pub const BOOT_REGION_SECTORS: u64 = 11;
/// Where the checksum sector sits within a boot region.
pub const BOOT_CHECKSUM_SECTOR: u64 = 11;
/// A boot region is twelve sectors; the backup begins after the main one.
pub const BOOT_REGION_LEN: u64 = 12;

/// Offsets within a stream extension entry.
pub const STREAM_OFF_FLAGS: usize = 1;
pub const STREAM_OFF_NAME_LEN: usize = 3;
pub const STREAM_OFF_NAME_HASH: usize = 4;
pub const STREAM_OFF_VALID_SIZE: usize = 8;
pub const STREAM_OFF_START_CLU: usize = 20;
pub const STREAM_OFF_SIZE: usize = 24;

/// Offsets within a name entry.
pub const NAME_OFF_FLAGS: usize = 1;
pub const NAME_OFF_CHARS: usize = 2;

/// Offsets within an allocation-bitmap entry.
pub const BITMAP_OFF_FLAGS: usize = 1;
pub const BITMAP_OFF_START_CLU: usize = 20;
pub const BITMAP_OFF_SIZE: usize = 24;

/// Offsets within an up-case table entry.
pub const UPCASE_OFF_CHECKSUM: usize = 4;
pub const UPCASE_OFF_START_CLU: usize = 20;
pub const UPCASE_OFF_SIZE: usize = 24;

/// Offsets within a volume-label entry.
pub const LABEL_OFF_CHAR_COUNT: usize = 1;
pub const LABEL_OFF_CHARS: usize = 2;

/// Offsets within any generic secondary entry.
pub const SECONDARY_OFF_FLAGS: usize = 1;
pub const SECONDARY_OFF_START_CLU: usize = 20;
pub const SECONDARY_OFF_SIZE: usize = 24;

/// Entries in a fully expanded up-case table.
pub const UPCASE_ENTRIES: usize = 0x10000;
/// The unit that marks a compressed run in an up-case table.
pub const UPCASE_SKIP_MARKER: u16 = 0xFFFF;
