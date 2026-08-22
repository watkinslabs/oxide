//! The on-disk numbers NTFS is defined in terms of.

/// The eight bytes at offset three that say a volume is NTFS.
pub const SYSTEM_ID: &[u8; 8] = b"NTFS    ";

/// Offsets into the boot sector.
pub const BOOT_OFF_SYSTEM_ID: usize = 0x03;
pub const BOOT_OFF_BYTES_PER_SECTOR: usize = 0x0B;
pub const BOOT_OFF_SECTORS_PER_CLUSTER: usize = 0x0D;
pub const BOOT_OFF_MEDIA_TYPE: usize = 0x15;
pub const BOOT_OFF_HIDDEN_SECTORS: usize = 0x1C;
pub const BOOT_OFF_SECTORS_PER_VOLUME: usize = 0x28;
pub const BOOT_OFF_MFT_CLST: usize = 0x30;
pub const BOOT_OFF_MFT2_CLST: usize = 0x38;
pub const BOOT_OFF_RECORD_SIZE: usize = 0x40;
pub const BOOT_OFF_INDEX_SIZE: usize = 0x44;
pub const BOOT_OFF_SERIAL: usize = 0x48;
pub const BOOT_BYTES: usize = 0x200;

/// The unit every fixup covers, and the smallest sector the format admits.
pub const SECTOR_BYTES: usize = 512;
pub const SECTOR_SHIFT: u32 = 9;

/// The widest MFT record and index record the reference accepts, and the
/// widest shift a negative size field may name.
pub const MAX_BYTES_PER_MFT: u32 = 4096;
pub const MAX_SHIFT_BYTES_PER_MFT: i8 = 12;
pub const MAX_BYTES_PER_INDEX: u32 = 0x1_0000;
pub const MAX_SHIFT_BYTES_PER_INDEX: i8 = 16;

/// Fixed MFT record numbers.
pub const MFT_REC_MFT: u64 = 0;
pub const MFT_REC_MIRR: u64 = 1;
pub const MFT_REC_LOG: u64 = 2;
pub const MFT_REC_VOL: u64 = 3;
pub const MFT_REC_ATTR: u64 = 4;
pub const MFT_REC_ROOT: u64 = 5;
pub const MFT_REC_BITMAP: u64 = 6;
pub const MFT_REC_BOOT: u64 = 7;
pub const MFT_REC_BADCLUST: u64 = 8;
pub const MFT_REC_SECURE: u64 = 9;
pub const MFT_REC_UPCASE: u64 = 10;
pub const MFT_REC_EXTEND: u64 = 11;
/// The first record a user file may occupy.
pub const MFT_REC_USER: u64 = 24;

/// Record signatures, as they read on the medium.
pub const SIG_FILE: &[u8; 4] = b"FILE";
pub const SIG_INDX: &[u8; 4] = b"INDX";
pub const SIG_BAAD: &[u8; 4] = b"BAAD";
pub const SIG_CHKD: &[u8; 4] = b"CHKD";

/// Offsets within the record header every fixed-up structure begins with.
pub const REC_OFF_SIGN: usize = 0x00;
pub const REC_OFF_FIX_OFF: usize = 0x04;
pub const REC_OFF_FIX_NUM: usize = 0x06;
pub const REC_OFF_LSN: usize = 0x08;
pub const REC_HEADER_BYTES: usize = 0x10;

/// Offsets within an MFT record.
pub const MFT_OFF_SEQ: usize = 0x10;
pub const MFT_OFF_HARD_LINKS: usize = 0x12;
pub const MFT_OFF_ATTR_OFF: usize = 0x14;
pub const MFT_OFF_FLAGS: usize = 0x16;
pub const MFT_OFF_USED: usize = 0x18;
pub const MFT_OFF_TOTAL: usize = 0x1C;
pub const MFT_OFF_PARENT_REF: usize = 0x20;
pub const MFT_OFF_NEXT_ATTR_ID: usize = 0x28;
pub const MFT_OFF_RECORD_NUM: usize = 0x2C;
/// The two places a record's fixup array may begin.
pub const MFT_FIXUP_OFFSET_SMALL: u16 = 0x2A;
pub const MFT_FIXUP_OFFSET_LARGE: u16 = 0x30;

/// Record flags.
pub const RECORD_FLAG_IN_USE: u16 = 0x0001;
pub const RECORD_FLAG_DIR: u16 = 0x0002;
pub const RECORD_FLAG_SYSTEM: u16 = 0x0004;
pub const RECORD_FLAG_INDEX: u16 = 0x0008;

/// Attribute types.
pub const ATTR_STD: u32 = 0x10;
pub const ATTR_LIST: u32 = 0x20;
pub const ATTR_NAME: u32 = 0x30;
pub const ATTR_ID: u32 = 0x40;
pub const ATTR_SECURE: u32 = 0x50;
pub const ATTR_LABEL: u32 = 0x60;
pub const ATTR_VOL_INFO: u32 = 0x70;
pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_ROOT: u32 = 0x90;
pub const ATTR_ALLOC: u32 = 0xA0;
pub const ATTR_BITMAP: u32 = 0xB0;
pub const ATTR_REPARSE: u32 = 0xC0;
pub const ATTR_EA_INFO: u32 = 0xD0;
pub const ATTR_EA: u32 = 0xE0;
pub const ATTR_PROPERTYSET: u32 = 0xF0;
pub const ATTR_LOGGED_UTILITY_STREAM: u32 = 0x100;
/// The marker that ends a record's attribute list.
pub const ATTR_END: u32 = 0xFFFF_FFFF;

/// Offsets common to every attribute header.
pub const ATTR_OFF_TYPE: usize = 0x00;
pub const ATTR_OFF_SIZE: usize = 0x04;
pub const ATTR_OFF_NON_RES: usize = 0x08;
pub const ATTR_OFF_NAME_LEN: usize = 0x09;
pub const ATTR_OFF_NAME_OFF: usize = 0x0A;
pub const ATTR_OFF_FLAGS: usize = 0x0C;
pub const ATTR_OFF_ID: usize = 0x0E;

/// Offsets within a resident attribute.
pub const RES_OFF_DATA_SIZE: usize = 0x10;
pub const RES_OFF_DATA_OFF: usize = 0x14;
pub const RES_OFF_FLAGS: usize = 0x16;
pub const SIZEOF_RESIDENT: usize = 0x18;

/// Offsets within a non-resident attribute.
pub const NRES_OFF_SVCN: usize = 0x10;
pub const NRES_OFF_EVCN: usize = 0x18;
pub const NRES_OFF_RUN_OFF: usize = 0x20;
pub const NRES_OFF_C_UNIT: usize = 0x22;
pub const NRES_OFF_ALLOC_SIZE: usize = 0x28;
pub const NRES_OFF_DATA_SIZE: usize = 0x30;
pub const NRES_OFF_VALID_SIZE: usize = 0x38;
pub const NRES_OFF_TOTAL_SIZE: usize = 0x40;
pub const SIZEOF_NONRESIDENT: usize = 0x40;
pub const SIZEOF_NONRESIDENT_EX: usize = 0x48;

/// Attribute flags.
pub const ATTR_FLAG_COMPRESSED: u16 = 0x0001;
pub const ATTR_FLAG_COMPRESSED_MASK: u16 = 0x00FF;
pub const ATTR_FLAG_ENCRYPTED: u16 = 0x4000;
pub const ATTR_FLAG_SPARSED: u16 = 0x8000;
/// A resident attribute the volume indexes.
pub const RESIDENT_FLAG_INDEXED: u8 = 0x01;

/// File attributes, as `$STANDARD_INFORMATION` and a filename record them.
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
pub const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0000_0800;
pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
/// Not stored on disk in `$STANDARD_INFORMATION`; set in a filename record.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x1000_0000;

/// Offsets within `$STANDARD_INFORMATION`.
pub const STD_OFF_CR_TIME: usize = 0x00;
pub const STD_OFF_M_TIME: usize = 0x08;
pub const STD_OFF_C_TIME: usize = 0x10;
pub const STD_OFF_A_TIME: usize = 0x18;
pub const STD_OFF_FA: usize = 0x20;
pub const STD_OFF_OWNER_ID: usize = 0x30;
pub const STD_OFF_SECURITY_ID: usize = 0x34;
pub const SIZEOF_STD_INFO: usize = 0x30;
pub const SIZEOF_STD_INFO5: usize = 0x48;

/// Offsets within `$FILE_NAME`.
pub const FN_OFF_HOME: usize = 0x00;
pub const FN_OFF_CR_TIME: usize = 0x08;
pub const FN_OFF_M_TIME: usize = 0x10;
pub const FN_OFF_C_TIME: usize = 0x18;
pub const FN_OFF_A_TIME: usize = 0x20;
pub const FN_OFF_ALLOC_SIZE: usize = 0x28;
pub const FN_OFF_DATA_SIZE: usize = 0x30;
pub const FN_OFF_FA: usize = 0x38;
pub const FN_OFF_NAME_LEN: usize = 0x40;
pub const FN_OFF_TYPE: usize = 0x41;
pub const FN_OFF_NAME: usize = 0x42;
pub const SIZEOF_FILENAME_MIN: usize = 0x44;

/// The four namespaces a name can be recorded in.
pub const FILE_NAME_POSIX: u8 = 0;
pub const FILE_NAME_UNICODE: u8 = 1;
pub const FILE_NAME_DOS: u8 = 2;
pub const FILE_NAME_UNICODE_AND_DOS: u8 = FILE_NAME_DOS | FILE_NAME_UNICODE;

/// Longest name the format admits, in UTF-16 units.
pub const NTFS_NAME_LEN: usize = 255;

/// Longest volume label, in UTF-16 units. A name past it is refused.
pub const NTFS_LABEL_MAX: usize = 0x100 / 2;
/// Hard links one record admits.
pub const NTFS_LINK_MAX: u16 = 4000;

/// Offsets within an index entry.
pub const DE_OFF_REF: usize = 0x00;
pub const DE_OFF_SIZE: usize = 0x08;
pub const DE_OFF_KEY_SIZE: usize = 0x0A;
pub const DE_OFF_FLAGS: usize = 0x0C;
pub const SIZEOF_DE: usize = 0x10;

/// Index entry flags.
pub const NTFS_IE_HAS_SUBNODES: u16 = 1;
pub const NTFS_IE_LAST: u16 = 2;

/// Offsets within an index header.
pub const IHDR_OFF_DE_OFF: usize = 0x00;
pub const IHDR_OFF_USED: usize = 0x04;
pub const IHDR_OFF_TOTAL: usize = 0x08;
pub const IHDR_OFF_FLAGS: usize = 0x0C;
pub const SIZEOF_IHDR: usize = 0x10;
/// The index-header flag that says entries carry child pointers.
pub const INDEX_HDR_HAS_SUBNODES: u32 = 1;

/// Offsets within an index root attribute.
pub const IROOT_OFF_TYPE: usize = 0x00;
pub const IROOT_OFF_RULE: usize = 0x04;
pub const IROOT_OFF_BLOCK_SIZE: usize = 0x08;
pub const IROOT_OFF_BLOCK_CLST: usize = 0x0C;
pub const IROOT_OFF_IHDR: usize = 0x10;

/// Offsets within an index buffer.
pub const IB_OFF_VBN: usize = 0x10;
pub const IB_OFF_IHDR: usize = 0x18;

/// Collation rules an index can be ordered by.
pub const COLLATION_BINARY: u32 = 0x00;
pub const COLLATION_FILENAME: u32 = 0x01;
pub const COLLATION_UINT: u32 = 0x10;
pub const COLLATION_SID: u32 = 0x11;
pub const COLLATION_SECURITY_HASH: u32 = 0x12;
pub const COLLATION_UINTS: u32 = 0x13;

/// The name of the directory index every directory carries.
pub const I30_NAME: [u16; 4] = [0x24, 0x49, 0x33, 0x30];

/// Offsets within `$VOLUME_INFORMATION`.
pub const VOLINFO_OFF_MAJOR: usize = 0x08;
pub const VOLINFO_OFF_MINOR: usize = 0x09;
pub const VOLINFO_OFF_FLAGS: usize = 0x0A;
pub const SIZEOF_VOLUME_INFO: usize = 0x0C;

/// Volume flags.
pub const VOLUME_FLAG_DIRTY: u16 = 0x0001;
pub const VOLUME_FLAG_RESIZE_LOG_FILE: u16 = 0x0002;

/// Cluster numbers with a meaning of their own.
pub const SPARSE_LCN: u64 = u64::MAX;

/// Compression: a chunk is 4096 bytes, and the unit is sixteen clusters.
pub const LZNT_CHUNK_SIZE: usize = 0x1000;
pub const LZNT_CUNIT: u8 = 4;
pub const LZNT_CLUSTERS: u32 = 1 << LZNT_CUNIT;

/// Reparse tags this implementation acts on.
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
pub const IO_REPARSE_TAG_WOF: u32 = 0x8000_0017;
/// A tag with this bit set names a Microsoft-defined reparse point.
pub const IO_REPARSE_TAG_MICROSOFT: u32 = 0x8000_0000;
/// A tag with this bit set stands in for another named object.
pub const IO_REPARSE_TAG_NAME_SURROGATE: u32 = 0x2000_0000;
/// Bytes before a third-party reparse point's generic target payload.
pub const REPARSE_OFF_GENERIC_BUFFER: usize = 0x18;
/// Offsets within a reparse point's data.
pub const REPARSE_OFF_TAG: usize = 0x00;
pub const REPARSE_OFF_DATA_LEN: usize = 0x04;
pub const REPARSE_OFF_SYMLINK_SUB_OFF: usize = 0x08;
pub const REPARSE_OFF_SYMLINK_SUB_LEN: usize = 0x0A;
pub const REPARSE_OFF_SYMLINK_PRINT_OFF: usize = 0x0C;
pub const REPARSE_OFF_SYMLINK_PRINT_LEN: usize = 0x0E;
pub const REPARSE_OFF_SYMLINK_FLAGS: usize = 0x10;
pub const REPARSE_OFF_SYMLINK_BUFFER: usize = 0x14;
pub const REPARSE_OFF_MOUNT_BUFFER: usize = 0x10;
/// A symbolic link whose target is relative to the link.
pub const SYMLINK_FLAG_RELATIVE: u32 = 1;

/// Offsets within an attribute-list entry.
pub const LE_OFF_TYPE: usize = 0x00;
pub const LE_OFF_SIZE: usize = 0x04;
pub const LE_OFF_NAME_LEN: usize = 0x06;
pub const LE_OFF_NAME_OFF: usize = 0x07;
pub const LE_OFF_VCN: usize = 0x08;
pub const LE_OFF_REF: usize = 0x10;
pub const LE_OFF_ID: usize = 0x18;
pub const SIZEOF_LE_MIN: usize = 0x1A;

/// The magic a mounted NTFS volume reports.
pub const NTFS_SUPER_MAGIC: u64 = 0x5346_544E;
/// The root directory's inode number, which is its MFT record number.
pub const ROOT_INO: u64 = MFT_REC_ROOT;

/// Seconds between the NT epoch (1601-01-01) and the Unix epoch.
pub const NT_EPOCH_DELTA_SECS: i64 = 11_644_473_600;
/// Units of 100 nanoseconds in one second.
pub const NT_UNITS_PER_SEC: i64 = 10_000_000;
pub const NT_NSEC_PER_UNIT: u32 = 100;
