/// `FIEMAP_EXTENT_*` flags.
pub const FIEMAP_EXTENT_LAST:           u32 = 0x0001;
pub const FIEMAP_EXTENT_UNKNOWN:        u32 = 0x0002;
pub const FIEMAP_EXTENT_DELALLOC:       u32 = 0x0004;
pub const FIEMAP_EXTENT_ENCODED:        u32 = 0x0008;
pub const FIEMAP_EXTENT_DATA_ENCRYPTED: u32 = 0x0080;
pub const FIEMAP_EXTENT_NOT_ALIGNED:    u32 = 0x0100;
pub const FIEMAP_EXTENT_DATA_INLINE:    u32 = 0x0200;
pub const FIEMAP_EXTENT_UNWRITTEN:      u32 = 0x0800;
pub const FIEMAP_EXTENT_MERGED:         u32 = 0x1000;
pub const FIEMAP_EXTENT_SHARED:         u32 = 0x2000;

/// `FS_*_FL` inode flags.
pub const FS_SECRM_FL:     u32 = 0x0000_0001;
pub const FS_UNRM_FL:      u32 = 0x0000_0002;
pub const FS_COMPR_FL:     u32 = 0x0000_0004;
pub const FS_SYNC_FL:      u32 = 0x0000_0008;
pub const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub const FS_APPEND_FL:    u32 = 0x0000_0020;
pub const FS_NODUMP_FL:    u32 = 0x0000_0040;
pub const FS_NOATIME_FL:   u32 = 0x0000_0080;

pub const I_VERSION_QUERIED_SHIFT: u32 = 1;
pub const I_VERSION_QUERIED:       u64 = 1 << (I_VERSION_QUERIED_SHIFT - 1);
pub const I_VERSION_INCREMENT:     u64 = 1 << I_VERSION_QUERIED_SHIFT;

pub const S_ATIME:   u32 = 1 << 0;
pub const S_MTIME:   u32 = 1 << 1;
pub const S_CTIME:   u32 = 1 << 2;
pub const S_VERSION: u32 = 1 << 3;

pub const I_DIRTY_SYNC:     u32 = 1 << 0;
pub const I_DIRTY_DATASYNC: u32 = 1 << 1;
pub const I_DIRTY_PAGES:    u32 = 1 << 2;
pub const I_NEW:            u32 = 1 << 3;
pub const I_WILL_FREE:      u32 = 1 << 4;
pub const I_FREEING:        u32 = 1 << 5;
pub const I_CLEAR:          u32 = 1 << 6;
pub const I_DIRTY:          u32 = I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES;

pub const S_SYNC:      u32 = 1 << 0;
pub const S_NOATIME:   u32 = 1 << 1;
pub const S_APPEND:    u32 = 1 << 2;
pub const S_IMMUTABLE: u32 = 1 << 3;
pub const S_DEAD:      u32 = 1 << 4;
pub const S_DIRSYNC:   u32 = 1 << 6;
pub const S_DAX:       u32 = 1 << 13;
pub const S_ENCRYPTED: u32 = 1 << 14;
pub const S_CASEFOLD:  u32 = 1 << 15;
pub const S_VERITY:    u32 = 1 << 16;

pub const POLL_IN:    u32 = 0x0001;
pub const POLL_OUT:   u32 = 0x0004;
pub const POLL_HUP:   u32 = 0x0010;
pub const POLL_ERR:   u32 = 0x0008;
pub const POLL_PRI:   u32 = 0x0002;
pub const POLL_RDHUP: u32 = 0x2000;
