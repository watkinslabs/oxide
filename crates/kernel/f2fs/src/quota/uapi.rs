//! The on-disk numbers of a quota file: magics, offsets, widths.
//!
//! A quota file is an ordinary inode whose CONTENTS are a format this
//! filesystem does not define — the same bytes every filesystem with quota
//! support reads. Nothing here is f2fs-specific except which inode holds it.

/// Bits in the unit block limits are counted in. Limits are stored in these
/// units and usage is stored in BYTES; the two are not the same scale and
/// mixing them under-counts a limit by three orders of magnitude.
pub const SPACE_UNIT_BITS: u32 = 10;
/// Bytes in that unit.
pub const SPACE_UNIT: u64 = 1 << SPACE_UNIT_BITS;

/// Bits in one block of the quota file's own radix tree. Fixed by the format
/// and unrelated to the filesystem's block size.
pub const QT_BLOCK_BITS: u32 = 10;
/// Bytes in one such block.
pub const QT_BLOCK_SIZE: usize = 1 << QT_BLOCK_BITS;

/// Bytes of one little-endian field of each width the format uses.
pub const U32_LEN: usize = 4;
pub const U64_LEN: usize = 8;
pub const U16_LEN: usize = 2;

/// Bytes of one block reference, and the shift that divides by it. A tree
/// block is an array of these, so both the fan-out and every level's index
/// arithmetic are derived from this width.
pub const REF_SIZE: usize = U32_LEN;
pub const REF_BITS: u32 = 2;

/// Block the tree's root sits at. Block zero holds the two headers.
pub const QT_TREE_OFF: u32 = 1;

/// Blocks a walk records: one per level, plus the leaf it ends at.
pub const MAX_PATH_BLOCKS: usize = MAX_TREE_DEPTH as usize + 1;

/// Deepest tree this build walks. The format's own depth is derived from the
/// block size and is smaller; this is the recursion bound, and it is what
/// keeps a corrupted header from being walked forever.
pub const MAX_TREE_DEPTH: u32 = 6;

// ------------------------------------------------------------------- header

pub const DQH_MAGIC: usize = 0;
pub const DQH_VERSION: usize = DQH_MAGIC + U32_LEN;
/// Bytes of the generic header at the front of the file.
pub const HEADER_SIZE: usize = DQH_VERSION + U32_LEN;

/// The magic a file of each type carries. A file mounted as the wrong type
/// decodes cleanly and accounts the wrong identity, so the magic is the only
/// thing that says which of the three a file is.
pub const MAGIC: [u32; MAX_QUOTAS] = [0xd9c0_1f11, 0xd9c0_1927, 0xd9c0_3f14];

/// The version word each revision writes.
pub const VERSION_R0: u32 = 0;
pub const VERSION_R1: u32 = 1;

/// Highest file version this build reads. Revision zero stores its limits in
/// four bytes; revision one in eight.
pub const MAX_VERSION: u32 = VERSION_R1;

// --------------------------------------------------------------------- info

/// The per-type header follows the generic one immediately.
pub const INFO_OFF: usize = HEADER_SIZE;
pub const DQI_BGRACE: usize = 0;
pub const DQI_IGRACE: usize = DQI_BGRACE + U32_LEN;
pub const DQI_FLAGS: usize = DQI_IGRACE + U32_LEN;
pub const DQI_BLOCKS: usize = DQI_FLAGS + U32_LEN;
pub const DQI_FREE_BLK: usize = DQI_BLOCKS + U32_LEN;
pub const DQI_FREE_ENTRY: usize = DQI_FREE_BLK + U32_LEN;
pub const INFO_SIZE: usize = DQI_FREE_ENTRY + U32_LEN;

/// Written into a record's inode-grace field to escape an otherwise-empty
/// record, which would else read as a free slot.
pub const EMPTY_ESCAPE: u64 = 1;

// ------------------------------------------------------------- block header

/// Every leaf block starts with this, and the entries follow it.
pub const DQDH_NEXT_FREE: usize = 0;
pub const DQDH_PREV_FREE: usize = DQDH_NEXT_FREE + U32_LEN;
pub const DQDH_ENTRIES: usize = DQDH_PREV_FREE + U32_LEN;
pub const DQDH_PAD: usize = DQDH_ENTRIES + U16_LEN;
/// Padded to a power of two so a leaf block holds a whole number of entries.
pub const DQDH_SIZE: usize = DQDH_PAD + U16_LEN + U32_LEN;

// ------------------------------------------------------------------ entries

/// Revision zero's record.
pub const R0_ID: usize = 0;
pub const R0_IHARDLIMIT: usize = R0_ID + U32_LEN;
pub const R0_ISOFTLIMIT: usize = R0_IHARDLIMIT + U32_LEN;
pub const R0_CURINODES: usize = R0_ISOFTLIMIT + U32_LEN;
pub const R0_BHARDLIMIT: usize = R0_CURINODES + U32_LEN;
pub const R0_BSOFTLIMIT: usize = R0_BHARDLIMIT + U32_LEN;
pub const R0_CURSPACE: usize = R0_BSOFTLIMIT + U32_LEN;
pub const R0_BTIME: usize = R0_CURSPACE + U64_LEN;
pub const R0_ITIME: usize = R0_BTIME + U64_LEN;
pub const R0_SIZE: usize = R0_ITIME + U64_LEN;

/// Revision one's record: every count widened to eight bytes, with a pad word
/// after the id so the widened fields stay aligned.
pub const R1_ID: usize = 0;
pub const R1_PAD: usize = R1_ID + U32_LEN;
pub const R1_IHARDLIMIT: usize = R1_PAD + U32_LEN;
pub const R1_ISOFTLIMIT: usize = R1_IHARDLIMIT + U64_LEN;
pub const R1_CURINODES: usize = R1_ISOFTLIMIT + U64_LEN;
pub const R1_BHARDLIMIT: usize = R1_CURINODES + U64_LEN;
pub const R1_BSOFTLIMIT: usize = R1_BHARDLIMIT + U64_LEN;
pub const R1_CURSPACE: usize = R1_BSOFTLIMIT + U64_LEN;
pub const R1_BTIME: usize = R1_CURSPACE + U64_LEN;
pub const R1_ITIME: usize = R1_BTIME + U64_LEN;
pub const R1_SIZE: usize = R1_ITIME + U64_LEN;

/// Widest limit revision zero can express, in bytes: a four-byte count of
/// space units.
pub const R0_MAX_SPACE_LIMIT: u64 = (u32::MAX as u64) << SPACE_UNIT_BITS;
/// Widest inode limit revision zero can express.
pub const R0_MAX_INODE_LIMIT: u64 = u32::MAX as u64;
/// Widest either quantity revision one can express. The count is unsigned on
/// disk but signed everywhere it is accounted, so the sign bit is not usable.
pub const R1_MAX_LIMIT: u64 = i64::MAX as u64;

// ----------------------------------------------------------------- identity

/// The three kinds, in the order the superblock lists their inodes.
pub const USRQUOTA: usize = 0;
pub const GRPQUOTA: usize = 1;
pub const PRJQUOTA: usize = 2;
pub const MAX_QUOTAS: usize = 3;

/// Attributes a quota inode carries: it is never dumped by timestamp and may
/// not be changed through the file interface.
pub const QUOTA_DEFAULT_FL: u32 = crate::flags::F2FS_NOATIME_FL | crate::flags::F2FS_IMMUTABLE_FL;
