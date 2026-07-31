pub(crate) const FIONREAD:  u64 = 0x541B;
#[allow(dead_code)]
pub(crate) const TIOCINQ:   u64 = FIONREAD;
#[allow(dead_code)]
pub(crate) const SIOCINQ:   u64 = FIONREAD;
pub(crate) const FIONBIO:   u64 = 0x5421;
pub(crate) const FIONCLEX:  u64 = 0x5450;
pub(crate) const FIOCLEX:   u64 = 0x5451;
pub(crate) const FIOASYNC:  u64 = 0x5452;
pub(crate) const FIOQSIZE:  u64 = 0x5460;
pub(crate) const FIBMAP:    u64 = 0x0000_0001;
pub(crate) const FIGETBSZ:  u64 = 0x0000_0002;
pub(crate) const FICLONE:   u64 = 0x4004_9409;
pub(crate) const FICLONERANGE: u64 = 0x4020_940D;
pub(crate) const FIDEDUPERANGE: u64 = 0xC018_9436;
pub(crate) const SIOCOUTQ:  u64 = 0x5411;
/// Socket `f_owner` controls from `asm-generic/sockios.h`.
pub(crate) const FIOSETOWN: u64 = 0x8901;
pub(crate) const SIOCSPGRP: u64 = 0x8902;
pub(crate) const FIOGETOWN: u64 = 0x8903;
pub(crate) const SIOCGPGRP: u64 = 0x8904;
pub(crate) const SIOCOUTQNSD: u64 = 0x894B;
pub(crate) const SIOCATMARK: u64 = 0x8905;
/// Linux `SIOCGSTAMP*` receive timestamp ioctls from `linux/sockios.h`.
pub(crate) const SIOCGSTAMP_OLD: u64 = 0x8906;
pub(crate) const SIOCGSTAMPNS_OLD: u64 = 0x8907;
pub(crate) const SIOCGSTAMP_NEW: u64 = 0x8010_8906;
pub(crate) const SIOCGSTAMPNS_NEW: u64 = 0x8010_8907;
pub(crate) const SOCKET_TIMESTAMP_BYTES: u64 = 16;
pub(crate) const NSEC_PER_SECOND: u64 = 1_000_000_000;
#[allow(dead_code)]
pub(crate) const TIOCOUTQ:  u64 = SIOCOUTQ;
pub(crate) const BLKROGET:   u64 = 0x125E;
pub(crate) const BLKGETSIZE:   u64 = 0x1260;
pub(crate) const BLKSSZGET:    u64 = 0x1268;
pub(crate) const BLKDISCARD:   u64 = 0x1277;
pub(crate) const BLKDISCARDZEROES: u64 = 0x127C;
pub(crate) const BLKSECDISCARD: u64 = 0x127D;
pub(crate) const BLKZEROOUT:   u64 = 0x127F;
pub(crate) const BLKBSZGET:    u64 = 0x8008_1270;
pub(crate) const BLKGETSIZE64: u64 = 0x8008_1272;
pub(crate) const INT_BYTES: u64 = 4;
pub(crate) const LOFF_BYTES: u64 = 8;
pub(crate) const PAGE_BYTES: u64 = 4096;

pub(crate) const FSXATTR_BYTES: u64 = 28;
pub(crate) const FSUUID2_BYTES: u64 = 17;
pub(crate) const EXT4_LABEL_MAX: usize = 16;
pub(crate) const EXT4_LABEL_BYTES: u64 = 17;
pub(crate) const FILE_CLONE_RANGE_BYTES: u64 = 32;
pub(crate) const DEDUPE_RANGE_BYTES: u64 = 24;
pub(crate) const DEDUPE_INFO_BYTES: u64 = 32;
pub(crate) const DEDUPE_SRC_OFFSET: u64 = 0;
pub(crate) const DEDUPE_SRC_LENGTH: u64 = 8;
pub(crate) const DEDUPE_DEST_COUNT: u64 = 16;
pub(crate) const DEDUPE_RESERVED1: u64 = 18;
pub(crate) const DEDUPE_RESERVED2: u64 = 20;
pub(crate) const DEDUPE_INFO_DEST_FD: u64 = 0;
pub(crate) const DEDUPE_INFO_DEST_OFFSET: u64 = 8;
pub(crate) const DEDUPE_INFO_BYTES_DEDUPED: u64 = 16;
pub(crate) const DEDUPE_INFO_STATUS: u64 = 24;
pub(crate) const DEDUPE_INFO_RESERVED: u64 = 28;
pub(crate) const SPACE_RESV_BYTES: u64 = 48;
pub(crate) const SPACE_RESV_L_WHENCE: u64 = 2;
pub(crate) const SPACE_RESV_L_START: u64 = 8;
pub(crate) const SPACE_RESV_L_LEN: u64 = 16;

pub(crate) const FS_IOC_RESVSP: u64 = 0x4030_5828;
pub(crate) const FS_IOC_UNRESVSP: u64 = 0x4030_5829;
pub(crate) const FS_IOC_RESVSP64: u64 = 0x4030_582A;
pub(crate) const FS_IOC_UNRESVSP64: u64 = 0x4030_582B;
pub(crate) const FS_IOC_ZERO_RANGE: u64 = 0x4030_5839;
pub(crate) const FS_IOC_GETFLAGS: u64 = 0x8008_6601;
pub(crate) const FS_IOC_SETFLAGS: u64 = 0x4008_6602;
pub(crate) const FS_IOC_GETVERSION: u64 = 0x8008_7601;
pub(crate) const FS_IOC_SETVERSION: u64 = 0x4008_7602;
pub(crate) const EXT4_IOC_GETVERSION: u64 = 0x8008_6603;
pub(crate) const EXT4_IOC_SETVERSION: u64 = 0x4008_6604;
pub(crate) const FS_IOC_FSGETXATTR: u64 = 0x801C_581F;
pub(crate) const FS_IOC_FSSETXATTR: u64 = 0x401C_5820;
pub(crate) const FS_IOC_GETFSUUID: u64 = 0x8011_1500;
pub(crate) const FS_IOC_GETFSSYSFSPATH: u64 = 0x8081_1501;
pub(crate) const FS_IOC_GETFSLABEL: u64 = 0x8100_9431;
pub(crate) const FS_IOC_SETFSLABEL: u64 = 0x4100_9432;
pub(crate) const FITRIM: u64 = 0xC018_5879;
pub(crate) const FSTRIM_RANGE_BYTES: u64 = 24;
pub(crate) const FS_SYSFS_PATH_BYTES: u64 = 129;
pub(crate) const FS_SYSFS_PATH_NAME_BYTES: usize = 128;

pub(crate) const SEEK_SET: i16 = 0;
pub(crate) const SEEK_CUR: i16 = 1;
pub(crate) const SEEK_END: i16 = 2;
pub(crate) const REMAP_FILE_DEDUP: u32 = 1;
pub(crate) const REMAP_FILE_CAN_SHORTEN: u32 = 2;
pub(crate) const FILE_DEDUPE_RANGE_SAME: i32 = 0;
pub(crate) const FILE_DEDUPE_RANGE_DIFFERS: i32 = 1;

// `FS_*_FL` / `FS_XFLAG_*` and the `include/linux/fileattr.h` masks are owned
// by `vfs::inode::flags` (the fileattr state they describe lives there); this
// module re-exports rather than re-declaring, so the two can never disagree.
pub(crate) use vfs::inode::{
    FS_APPEND_FL, FS_CASEFOLD_FL, FS_DAX_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, FS_NODUMP_FL,
    FS_PROJINHERIT_FL, FS_SYNC_FL, FS_VERITY_FL,
    FS_XFLAG_APPEND, FS_XFLAG_CASEFOLD, FS_XFLAG_DAX,
    FS_XFLAG_IMMUTABLE, FS_XFLAG_NOATIME, FS_XFLAG_NODUMP,
    FS_XFLAG_PROJINHERIT, FS_XFLAG_RDONLY_MASK, FS_XFLAG_SYNC, FS_XFLAG_VERITY, FS_XFLAGS_MASK,
};
