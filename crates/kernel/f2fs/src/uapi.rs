//! The on-disk numbers this format is defined in terms of.
//!
//! Offsets are byte offsets into the structure that owns them, spelled out
//! rather than derived from a Rust type: the on-disk layout is packed and
//! little-endian regardless of what any host would lay out, so a field's
//! position is a contract and not a consequence.

/// The magic every superblock carries, and the value `statfs` reports.
pub const F2FS_SUPER_MAGIC: u64 = 0xF2F5_2010;
/// Same number as the CRC seed and the magic comparison want it: 32 bits.
pub const MAGIC: u32 = 0xF2F5_2010;
/// The magic an extended-attribute region carries.
pub const XATTR_MAGIC: u32 = 0xF2F5_2011;

/// Byte offset of a superblock copy inside its block.
pub const SUPER_OFFSET: usize = 1024;
/// Bytes one superblock copy occupies, up to and including its CRC.
pub const SUPER_SIZE: usize = 3072;
/// How many superblock copies a volume carries, one per leading block.
pub const SUPER_COPIES: u64 = 2;

/// The one block size this build reads. The format ties the block to the
/// page, and both target arches page at four kibibytes.
pub const BLKSIZE: usize = 4096;
/// `log2(BLKSIZE)`, which the superblock must state.
pub const BLKSIZE_BITS: u32 = 12;
/// `log2` of the blocks one segment holds. Fixed by the format.
pub const LOG_BLKS_PER_SEG: u32 = 9;
/// Blocks per segment, given the above.
pub const BLKS_PER_SEG: u32 = 1 << LOG_BLKS_PER_SEG;

/// A block address meaning "no block": the hole reads as zeroes.
pub const NULL_ADDR: u32 = 0;
/// A block address meaning "reserved but not yet written": also a hole.
pub const NEW_ADDR: u32 = u32::MAX;
/// The head of a compressed cluster.
pub const COMPRESS_ADDR: u32 = u32::MAX - 1;

/// Node ids nothing may be allocated at.
pub const RESERVED_NODE_NUM: u32 = 3;

// ---------------------------------------------------------------- superblock

pub const SB_MAGIC: usize = 0;
pub const SB_MAJOR_VER: usize = 4;
pub const SB_MINOR_VER: usize = 6;
pub const SB_LOG_SECTORSIZE: usize = 8;
pub const SB_LOG_SECTORS_PER_BLOCK: usize = 12;
pub const SB_LOG_BLOCKSIZE: usize = 16;
pub const SB_LOG_BLOCKS_PER_SEG: usize = 20;
pub const SB_SEGS_PER_SEC: usize = 24;
pub const SB_SECS_PER_ZONE: usize = 28;
pub const SB_CHECKSUM_OFFSET: usize = 32;
pub const SB_BLOCK_COUNT: usize = 36;
pub const SB_SECTION_COUNT: usize = 44;
pub const SB_SEGMENT_COUNT: usize = 48;
pub const SB_SEGMENT_COUNT_CKPT: usize = 52;
pub const SB_SEGMENT_COUNT_SIT: usize = 56;
pub const SB_SEGMENT_COUNT_NAT: usize = 60;
pub const SB_SEGMENT_COUNT_SSA: usize = 64;
pub const SB_SEGMENT_COUNT_MAIN: usize = 68;
pub const SB_SEGMENT0_BLKADDR: usize = 72;
pub const SB_CP_BLKADDR: usize = 76;
pub const SB_SIT_BLKADDR: usize = 80;
pub const SB_NAT_BLKADDR: usize = 84;
pub const SB_SSA_BLKADDR: usize = 88;
pub const SB_MAIN_BLKADDR: usize = 92;
pub const SB_ROOT_INO: usize = 96;
pub const SB_NODE_INO: usize = 100;
pub const SB_META_INO: usize = 104;
pub const SB_UUID: usize = 108;
pub const SB_UUID_LEN: usize = 16;
pub const SB_VOLUME_NAME: usize = 124;
/// Volume name is UTF-16 code units, not bytes.
pub const SB_VOLUME_NAME_UNITS: usize = 512;
pub const SB_EXTENSION_COUNT: usize = 1148;
pub const SB_EXTENSION_LIST: usize = 1152;
pub const SB_CP_PAYLOAD: usize = 1664;
pub const SB_VERSION: usize = 1668;
pub const SB_INIT_VERSION: usize = 1924;
pub const SB_FEATURE: usize = 2180;
pub const SB_ENCRYPTION_LEVEL: usize = 2184;
pub const SB_ENCRYPT_PW_SALT: usize = 2185;
/// Bytes of that salt.
pub const PW_SALT_LEN: usize = 16;
pub const SB_DEVS: usize = 2201;
pub const SB_QF_INO: usize = 2745;
pub const SB_HOT_EXT_COUNT: usize = 2757;
pub const SB_S_ENCODING: usize = 2758;
pub const SB_S_ENCODING_FLAGS: usize = 2760;
pub const SB_S_STOP_REASON: usize = 2762;
pub const SB_S_ERRORS: usize = 2794;
pub const SB_RESERVED: usize = 2810;
/// The only value `checksum_offset` may hold: where the CRC itself sits.
pub const SB_CRC: usize = 3068;

/// Longest extension string, and how many the list holds.
pub const EXTENSION_LEN: usize = 8;
pub const MAX_EXTENSION: u32 = 64;
/// Entries in the device list, and the shape of one.
pub const MAX_DEVICES: usize = 8;
pub const DEV_PATH_LEN: usize = 64;
pub const DEV_ENTRY_SIZE: usize = 68;
pub const MAX_QUOTAS: usize = 3;

/// The encoding number `s_encoding` carries when the volume is case-folded.
pub const ENC_UTF8_12_1: u16 = 1;

// ---------------------------------------------------------------- checkpoint

pub const CP_CHECKPOINT_VER: usize = 0;
pub const CP_USER_BLOCK_COUNT: usize = 8;
pub const CP_VALID_BLOCK_COUNT: usize = 16;
pub const CP_RSVD_SEGMENT_COUNT: usize = 24;
pub const CP_OVERPROV_SEGMENT_COUNT: usize = 28;
pub const CP_FREE_SEGMENT_COUNT: usize = 32;
pub const CP_CUR_NODE_SEGNO: usize = 36;
pub const CP_CUR_NODE_BLKOFF: usize = 68;
pub const CP_CUR_DATA_SEGNO: usize = 84;
pub const CP_CUR_DATA_BLKOFF: usize = 116;
pub const CP_CKPT_FLAGS: usize = 132;
pub const CP_PACK_TOTAL_BLOCK_COUNT: usize = 136;
pub const CP_PACK_START_SUM: usize = 140;
pub const CP_VALID_NODE_COUNT: usize = 144;
pub const CP_VALID_INODE_COUNT: usize = 148;
pub const CP_NEXT_FREE_NID: usize = 152;
pub const CP_SIT_VER_BITMAP_BYTESIZE: usize = 156;
pub const CP_NAT_VER_BITMAP_BYTESIZE: usize = 160;
pub const CP_CHECKSUM_OFFSET_FIELD: usize = 164;
pub const CP_ELAPSED_TIME: usize = 168;
pub const CP_ALLOC_TYPE: usize = 176;
/// Where the two version bitmaps begin, and the lowest a CRC may sit at.
pub const CP_SIT_NAT_VERSION_BITMAP: usize = 192;
/// The highest offset the CRC may sit at: the block's last word.
pub const CP_MAX_CHKSUM_OFFSET: usize = BLKSIZE - 4;
/// Packs a volume alternates between.
pub const CP_PACKS: u32 = 2;

/// Logs of each kind the checkpoint records a current segment for.
pub const MAX_ACTIVE_NODE_LOGS: usize = 8;
pub const MAX_ACTIVE_DATA_LOGS: usize = 8;
pub const MAX_ACTIVE_LOGS: usize = 16;

// --------------------------------------------------------------------- nodes

/// Bytes of the footer every node block ends with.
pub const NODE_FOOTER_SIZE: usize = 24;
/// Where that footer starts.
pub const NODE_FOOTER_OFF: usize = BLKSIZE - NODE_FOOTER_SIZE;
pub const FOOTER_NID: usize = 0;
pub const FOOTER_INO: usize = 4;
pub const FOOTER_FLAG: usize = 8;
pub const FOOTER_CP_VER: usize = 12;
pub const FOOTER_NEXT_BLKADDR: usize = 20;

/// Where `i_ext` ends, which is where the address array or the extra
/// attributes begin.
pub const OFFSET_OF_END_OF_I_EXT: usize = 360;
/// Bytes the five node ids at the end of an inode occupy.
pub const SIZE_OF_I_NID: usize = 20;
/// Addresses an inode block holds when nothing is carved out of them.
pub const DEF_ADDRS_PER_INODE: usize =
    (BLKSIZE - OFFSET_OF_END_OF_I_EXT - SIZE_OF_I_NID - NODE_FOOTER_SIZE) / 4;
/// Addresses a direct node block holds.
pub const DEF_ADDRS_PER_BLOCK: usize = (BLKSIZE - NODE_FOOTER_SIZE) / 4;
/// Node ids an indirect node block holds.
pub const NIDS_PER_BLOCK: usize = DEF_ADDRS_PER_BLOCK;
/// Node ids an inode carries.
pub const DEF_NIDS_PER_INODE: usize = 5;
/// Where `i_nid[0]` sits.
pub const I_NID_OFF: usize = OFFSET_OF_END_OF_I_EXT + DEF_ADDRS_PER_INODE * 4;

/// The `offset[0]` values that name each of the five node ids.
pub const NODE_DIR1_BLOCK: usize = DEF_ADDRS_PER_INODE + 1;
pub const NODE_DIR2_BLOCK: usize = DEF_ADDRS_PER_INODE + 2;
pub const NODE_IND1_BLOCK: usize = DEF_ADDRS_PER_INODE + 3;
pub const NODE_IND2_BLOCK: usize = DEF_ADDRS_PER_INODE + 4;
pub const NODE_DIND_BLOCK: usize = DEF_ADDRS_PER_INODE + 5;

/// Addresses reserved ahead of inline data inside the address array.
pub const INLINE_RESERVED_SIZE: usize = 1;
/// Addresses an inode reserves for inline attributes when it reserves any and
/// the volume does not state its own number.
pub const DEFAULT_INLINE_XATTR_ADDRS: usize = 50;

// ------------------------------------------------------------------- inode

pub const I_MODE: usize = 0;
pub const I_ADVISE: usize = 2;
pub const I_INLINE: usize = 3;
pub const I_UID: usize = 4;
pub const I_GID: usize = 8;
pub const I_LINKS: usize = 12;
pub const I_SIZE: usize = 16;
pub const I_BLOCKS: usize = 24;
pub const I_ATIME: usize = 32;
pub const I_CTIME: usize = 40;
pub const I_MTIME: usize = 48;
pub const I_ATIME_NSEC: usize = 56;
pub const I_CTIME_NSEC: usize = 60;
pub const I_MTIME_NSEC: usize = 64;
pub const I_GENERATION: usize = 68;
pub const I_CURRENT_DEPTH: usize = 72;
pub const I_XATTR_NID: usize = 76;
pub const I_FLAGS: usize = 80;
pub const I_PINO: usize = 84;
pub const I_NAMELEN: usize = 88;
pub const I_NAME: usize = 92;
pub const I_DIR_LEVEL: usize = 347;
pub const I_EXT: usize = 348;
pub const I_EXT_FOFS: usize = 348;
pub const I_EXT_BLK: usize = 352;
pub const I_EXT_LEN: usize = 356;

/// Extra attributes, which overlay the head of the address array.
pub const I_EXTRA_ISIZE: usize = 360;
pub const I_INLINE_XATTR_SIZE: usize = 362;
pub const I_PROJID: usize = 364;
pub const I_INODE_CHECKSUM: usize = 368;
pub const I_CRTIME: usize = 372;
pub const I_CRTIME_NSEC: usize = 380;
pub const I_COMPR_BLOCKS: usize = 384;
pub const I_COMPRESS_ALGORITHM: usize = 392;
pub const I_LOG_CLUSTER_SIZE: usize = 393;
pub const I_COMPRESS_FLAG: usize = 394;
/// Widest `i_extra_isize` the layout admits.
pub const TOTAL_EXTRA_ATTR_SIZE: usize = 36;
/// Narrowest one a volume may declare.
pub const MIN_EXTRA_ATTR_SIZE: usize = 4;

/// Longest name this filesystem stores.
pub const NAME_LEN: usize = 255;

// ----------------------------------------------------------------- nat / sit

pub const NAT_ENTRY_SIZE: usize = 9;
pub const NAT_ENTRY_PER_BLOCK: usize = BLKSIZE / NAT_ENTRY_SIZE;
pub const NAT_VERSION: usize = 0;
pub const NAT_INO: usize = 1;
pub const NAT_BLOCK_ADDR: usize = 5;

pub const SIT_VBLOCK_MAP_SIZE: usize = 64;
pub const SIT_ENTRY_SIZE: usize = 74;
pub const SIT_ENTRY_PER_BLOCK: usize = BLKSIZE / SIT_ENTRY_SIZE;
pub const SIT_VBLOCKS: usize = 0;
pub const SIT_VALID_MAP: usize = 2;
pub const SIT_MTIME: usize = 66;
/// `vblocks` splits into a count and an allocation type at this bit.
pub const SIT_VBLOCKS_SHIFT: u32 = 10;
pub const SIT_VBLOCKS_MASK: u16 = (1 << SIT_VBLOCKS_SHIFT) - 1;

// -------------------------------------------------------------- summary block

pub const SUMMARY_SIZE: usize = 7;
pub const SUM_FOOTER_SIZE: usize = 5;
/// Summary entries one block covers, one per block of the segment.
pub const ENTRIES_IN_SUM: usize = BLKSIZE / 8;
/// Where the journal begins inside a summary block.
pub const SUM_JOURNAL_OFF: usize = SUMMARY_SIZE * ENTRIES_IN_SUM;
/// Bytes of journal between the entries and the footer.
pub const SUM_JOURNAL_SIZE: usize = BLKSIZE - SUM_FOOTER_SIZE - SUM_JOURNAL_OFF;
/// One journalled NAT entry: the nid, then the entry.
pub const NAT_JOURNAL_ENTRY_SIZE: usize = 4 + NAT_ENTRY_SIZE;
pub const SIT_JOURNAL_ENTRY_SIZE: usize = 4 + SIT_ENTRY_SIZE;
/// Journalled entries of each kind that fit, past the two-byte count.
pub const NAT_JOURNAL_ENTRIES: usize = (SUM_JOURNAL_SIZE - 2) / NAT_JOURNAL_ENTRY_SIZE;
pub const SIT_JOURNAL_ENTRIES: usize = (SUM_JOURNAL_SIZE - 2) / SIT_JOURNAL_ENTRY_SIZE;

/// Current-segment logs, in the order the checkpoint records them.
pub const CURSEG_HOT_DATA: usize = 0;
pub const CURSEG_WARM_DATA: usize = 1;
pub const CURSEG_COLD_DATA: usize = 2;
pub const CURSEG_HOT_NODE: usize = 3;
pub const CURSEG_WARM_NODE: usize = 4;
pub const CURSEG_COLD_NODE: usize = 5;
pub const NR_CURSEG_DATA_TYPE: usize = 3;
pub const NR_CURSEG_NODE_TYPE: usize = 3;
pub const NR_CURSEG_PERSIST_TYPE: usize = NR_CURSEG_DATA_TYPE + NR_CURSEG_NODE_TYPE;
/// Logs a volume marked read-only at format time was written through, and
/// therefore all the current-segment slots its checkpoint records.
pub const NR_CURSEG_RO_TYPE: usize = 2;
/// The log a PINNED file's blocks are taken from.
///
/// Not one of the six the checkpoint records: it exists only while the volume
/// is mounted, is opened a whole SECTION at a time, and its segment is handed
/// back or its summary written to the summary area when a checkpoint lands.
/// A pinned file's blocks must never be moved, so they may not share a section
/// with blocks the cleaner is free to relocate.
pub const CURSEG_COLD_DATA_PINNED: usize = 6;
/// The log the age-threshold cleaner writes what it moves into.
///
/// Also not one of the six. It recycles a partly-used cold-data segment rather
/// than opening an empty one, which is the point: blocks the cleaner moves are
/// old and are being placed beside data of their own age, so the section they
/// land in ages as a unit and becomes worth cleaning as a unit. Mixing them
/// into the ordinary cold log would spread old blocks through segments that
/// are still being appended to and defeat the age policy that chose them.
pub const CURSEG_ALL_DATA_ATGC: usize = 7;
/// Logs that exist in memory only.
pub const NR_CURSEG_INMEM_TYPE: usize = 2;
/// Logs a mount carries, persisted and in-memory together.
pub const NR_CURSEG_TYPE: usize = NR_CURSEG_PERSIST_TYPE + NR_CURSEG_INMEM_TYPE;

/// The segment number that means "no segment": a log with nothing open.
pub const NULL_SEGNO: u32 = u32::MAX;

/// How a log picks the next block inside its segment.
pub const ALLOC_LFS: u8 = 0;
pub const ALLOC_SSR: u8 = 1;

/// Byte offset of summary entry `n` inside a summary block.
pub const fn summary_off(n: usize) -> usize { n * SUMMARY_SIZE }

/// Where a segment's summary block lives in the summary area. # C: O(1)
pub const fn sum_block_addr(ssa_blkaddr: u32, segno: u32) -> u32 { ssa_blkaddr + segno }

// -------------------------------------------------------------- directories

/// Bytes one directory entry record occupies, name excluded.
pub const SIZE_OF_DIR_ENTRY: usize = 11;
/// Bytes of name one slot holds; a longer name spans several.
pub const SLOT_LEN: usize = 8;
pub const SLOT_LEN_BITS: usize = 3;
pub const DE_HASH_CODE: usize = 0;
pub const DE_INO: usize = 4;
pub const DE_NAME_LEN: usize = 8;
pub const DE_FILE_TYPE: usize = 10;

/// Entries a full dentry block holds, and the bitmap and padding ahead of
/// them.
pub const NR_DENTRY_IN_BLOCK: usize = (8 * BLKSIZE) / ((SIZE_OF_DIR_ENTRY + SLOT_LEN) * 8 + 1);
pub const SIZE_OF_DENTRY_BITMAP: usize = NR_DENTRY_IN_BLOCK.div_ceil(8);
pub const SIZE_OF_RESERVED: usize =
    BLKSIZE - ((SIZE_OF_DIR_ENTRY + SLOT_LEN) * NR_DENTRY_IN_BLOCK + SIZE_OF_DENTRY_BITMAP);

/// Deepest hash level a directory may reach, and the widest one level gets.
pub const MAX_DIR_HASH_DEPTH: u32 = 63;
pub const MAX_DIR_BUCKETS: u32 = 1 << ((MAX_DIR_HASH_DEPTH / 2) - 1);
/// The collision marker of the format's wider hash type. It sits above every
/// bit a stored 32-bit hash has, so masking it off a stored hash changes
/// nothing — a build that clears bit 31 instead computes a different hash for
/// half of all names.
pub const HASH_COL_BIT: u64 = 1 << 63;
/// The widest value a stored name hash can take.
pub const MAX_HASH: u64 = !(0x3u64 << 62);

// ------------------------------------------------------------------- xattrs

pub const XATTR_HEADER_SIZE: usize = 24;
pub const XATTR_H_MAGIC: usize = 0;
pub const XATTR_H_REFCOUNT: usize = 4;
pub const XATTR_ENTRY_HEADER: usize = 4;
pub const XATTR_E_NAME_INDEX: usize = 0;
pub const XATTR_E_NAME_LEN: usize = 1;
pub const XATTR_E_VALUE_SIZE: usize = 2;
/// Entries are aligned up to a four-byte boundary.
pub const XATTR_ROUND: usize = 3;
/// Bytes of an out-of-line attribute block that carry attributes.
pub const VALID_XATTR_BLOCK_SIZE: usize = BLKSIZE - NODE_FOOTER_SIZE;

/// Name-index values, which stand in for the prefix a name is shown with.
pub const XATTR_INDEX_USER: u8 = 1;
pub const XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
pub const XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
pub const XATTR_INDEX_TRUSTED: u8 = 4;
pub const XATTR_INDEX_LUSTRE: u8 = 5;
pub const XATTR_INDEX_SECURITY: u8 = 6;
pub const XATTR_INDEX_ADVISE: u8 = 7;
pub const XATTR_INDEX_ENCRYPTION: u8 = 9;
pub const XATTR_INDEX_VERITY: u8 = 11;

/// Align an attribute record's length up. # C: O(1)
pub const fn xattr_align(size: usize) -> usize { (size + XATTR_ROUND) & !XATTR_ROUND }

/// Slots a name of `len` bytes occupies. # C: O(1)
pub const fn dentry_slots(len: usize) -> usize { len.div_ceil(SLOT_LEN) }

/// Read a little-endian `u16` at `off`, or `None` past the end. # C: O(1)
pub fn le16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

/// Read a little-endian `u32` at `off`. # C: O(1)
pub fn le32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// Read a little-endian `u64` at `off`. # C: O(1)
pub fn le64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}
