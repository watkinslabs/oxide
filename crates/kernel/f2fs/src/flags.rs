//! The bit words: volume features, checkpoint state, inline layout, inode
//! attributes and the type byte a directory entry carries.

// ------------------------------------------------------------------ features

pub const FEATURE_ENCRYPT: u32 = 0x0000_0001;
pub const FEATURE_BLKZONED: u32 = 0x0000_0002;
pub const FEATURE_ATOMIC_WRITE: u32 = 0x0000_0004;
pub const FEATURE_EXTRA_ATTR: u32 = 0x0000_0008;
pub const FEATURE_PRJQUOTA: u32 = 0x0000_0010;
pub const FEATURE_INODE_CHKSUM: u32 = 0x0000_0020;
pub const FEATURE_FLEXIBLE_INLINE_XATTR: u32 = 0x0000_0040;
pub const FEATURE_QUOTA_INO: u32 = 0x0000_0080;
pub const FEATURE_INODE_CRTIME: u32 = 0x0000_0100;
pub const FEATURE_LOST_FOUND: u32 = 0x0000_0200;
pub const FEATURE_VERITY: u32 = 0x0000_0400;
pub const FEATURE_SB_CHKSUM: u32 = 0x0000_0800;
pub const FEATURE_CASEFOLD: u32 = 0x0000_1000;
pub const FEATURE_COMPRESSION: u32 = 0x0000_2000;
pub const FEATURE_RO: u32 = 0x0000_4000;
pub const FEATURE_DEVICE_ALIAS: u32 = 0x0000_8000;
pub const FEATURE_PACKED_SSA: u32 = 0x0001_0000;

// ---------------------------------------------------------------- checkpoint

pub const CP_RESIZEFS_FLAG: u32 = 0x0000_4000;
pub const CP_DISABLED_QUICK_FLAG: u32 = 0x0000_2000;
pub const CP_DISABLED_FLAG: u32 = 0x0000_1000;
pub const CP_QUOTA_NEED_FSCK_FLAG: u32 = 0x0000_0800;
pub const CP_LARGE_NAT_BITMAP_FLAG: u32 = 0x0000_0400;
pub const CP_NOCRC_RECOVERY_FLAG: u32 = 0x0000_0200;
pub const CP_TRIMMED_FLAG: u32 = 0x0000_0100;
pub const CP_NAT_BITS_FLAG: u32 = 0x0000_0080;
pub const CP_CRC_RECOVERY_FLAG: u32 = 0x0000_0040;
pub const CP_FASTBOOT_FLAG: u32 = 0x0000_0020;
pub const CP_FSCK_FLAG: u32 = 0x0000_0010;
pub const CP_ERROR_FLAG: u32 = 0x0000_0008;
pub const CP_COMPACT_SUM_FLAG: u32 = 0x0000_0004;
pub const CP_ORPHAN_PRESENT_FLAG: u32 = 0x0000_0002;
pub const CP_UMOUNT_FLAG: u32 = 0x0000_0001;

// -------------------------------------------------------------- inode inline

pub const INLINE_XATTR: u8 = 0x01;
pub const INLINE_DATA: u8 = 0x02;
pub const INLINE_DENTRY: u8 = 0x04;
pub const DATA_EXIST: u8 = 0x08;
pub const INLINE_DOTS: u8 = 0x10;
pub const EXTRA_ATTR: u8 = 0x20;
pub const PIN_FILE: u8 = 0x40;
pub const COMPRESS_RELEASED: u8 = 0x80;

// ------------------------------------------------------------- inode i_flags

pub const F2FS_COMPR_FL: u32 = 0x0000_0004;
pub const F2FS_SYNC_FL: u32 = 0x0000_0008;
pub const F2FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub const F2FS_APPEND_FL: u32 = 0x0000_0020;
pub const F2FS_NODUMP_FL: u32 = 0x0000_0040;
pub const F2FS_NOATIME_FL: u32 = 0x0000_0080;
pub const F2FS_NOCOMP_FL: u32 = 0x0000_0400;
pub const F2FS_ENCRYPT_FL: u32 = 0x0000_0800;
pub const F2FS_INDEX_FL: u32 = 0x0000_1000;
pub const F2FS_DIRSYNC_FL: u32 = 0x0001_0000;
pub const F2FS_PROJINHERIT_FL: u32 = 0x2000_0000;
pub const F2FS_CASEFOLD_FL: u32 = 0x4000_0000;
pub const F2FS_VERITY_FL: u32 = 0x0010_0000;
/// The file stands for a whole member device rather than holding data of its
/// own. Highest bit, so it is not one an ordinary attribute call can set.
pub const F2FS_DEVICE_ALIAS_FL: u32 = 0x8000_0000;

// ------------------------------------------------------------ node footer bit

/// The footer flag bit that marks a node block as belonging to a file rather
/// than a directory.
pub const COLD_BIT_SHIFT: u32 = 0;
/// The footer flag bit that marks a node block as one an `fsync` made
/// durable, which is what a recovery walk selects on.
pub const FSYNC_BIT_SHIFT: u32 = 1;
/// The footer flag bit that marks a node block as holding a directory's data.
pub const DENT_BIT_SHIFT: u32 = 2;
/// Bits above this one carry the node's offset within its inode.
pub const OFFSET_BIT_SHIFT: u32 = 3;
pub const OFFSET_BIT_MASK: u32 = (1 << OFFSET_BIT_SHIFT) - 1;

// ------------------------------------------------------------- inode i_advise

/// The file's blocks are not expected to be rewritten, so moving them costs
/// fragmentation and buys nothing: a write to one lands where it already lies.
pub const FADVISE_COLD_BIT: u8 = 0x01;
/// The inode has lost track of its parent, so a recovery cannot trust `i_pino`.
pub const FADVISE_LOST_PINO_BIT: u8 = 0x02;
/// The name recorded in the inode is CIPHERTEXT, so nothing may print it or
/// treat it as text.
pub const FADVISE_ENC_NAME_BIT: u8 = 0x08;
/// The inode's size must not be changed by a write past its end.
pub const FADVISE_KEEP_SIZE_BIT: u8 = 0x10;

// ------------------------------------------------------------------ file type

pub const FT_UNKNOWN: u8 = 0;
pub const FT_REG_FILE: u8 = 1;
pub const FT_DIR: u8 = 2;
pub const FT_CHRDEV: u8 = 3;
pub const FT_BLKDEV: u8 = 4;
pub const FT_FIFO: u8 = 5;
pub const FT_SOCK: u8 = 6;
pub const FT_SYMLINK: u8 = 7;
pub const FT_MAX: u8 = 8;
