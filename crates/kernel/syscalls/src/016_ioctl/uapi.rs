pub(super) const FIONREAD:  u64 = 0x541B;
#[allow(dead_code)]
pub(super) const TIOCINQ:   u64 = FIONREAD;
#[allow(dead_code)]
pub(super) const SIOCINQ:   u64 = FIONREAD;
pub(super) const FIONBIO:   u64 = 0x5421;
pub(super) const FIONCLEX:  u64 = 0x5450;
pub(super) const FIOCLEX:   u64 = 0x5451;
pub(super) const FIOASYNC:  u64 = 0x5452;
pub(super) const FIOQSIZE:  u64 = 0x5460;
pub(super) const FIBMAP:    u64 = 0x0000_0001;
pub(super) const FIGETBSZ:  u64 = 0x0000_0002;
pub(super) const FICLONE:   u64 = 0x4004_9409;
pub(super) const FICLONERANGE: u64 = 0x4020_940D;
pub(super) const FIDEDUPERANGE: u64 = 0xC018_9436;
pub(super) const SIOCOUTQ:  u64 = 0x5411;
/// Socket `f_owner` controls from `asm-generic/sockios.h`.
pub(super) const FIOSETOWN: u64 = 0x8901;
pub(super) const SIOCSPGRP: u64 = 0x8902;
pub(super) const FIOGETOWN: u64 = 0x8903;
pub(super) const SIOCGPGRP: u64 = 0x8904;
pub(super) const SIOCOUTQNSD: u64 = 0x894B;
pub(super) const SIOCATMARK: u64 = 0x8905;
/// Linux `SIOCGSTAMP*` receive timestamp ioctls from `linux/sockios.h`.
pub(super) const SIOCGSTAMP_OLD: u64 = 0x8906;
pub(super) const SIOCGSTAMPNS_OLD: u64 = 0x8907;
pub(super) const SIOCGSTAMP_NEW: u64 = 0x8010_8906;
pub(super) const SIOCGSTAMPNS_NEW: u64 = 0x8010_8907;
pub(super) const SOCKET_TIMESTAMP_BYTES: u64 = 16;
pub(super) const NSEC_PER_SECOND: u64 = 1_000_000_000;
#[allow(dead_code)]
pub(super) const TIOCOUTQ:  u64 = SIOCOUTQ;
pub(super) const BLKROGET:   u64 = 0x125E;
pub(super) const BLKGETSIZE:   u64 = 0x1260;
pub(super) const BLKSSZGET:    u64 = 0x1268;
pub(super) const BLKDISCARD:   u64 = 0x1277;
pub(super) const BLKDISCARDZEROES: u64 = 0x127C;
pub(super) const BLKSECDISCARD: u64 = 0x127D;
pub(super) const BLKZEROOUT:   u64 = 0x127F;
pub(super) const BLKBSZGET:    u64 = 0x8008_1270;
pub(super) const BLKGETSIZE64: u64 = 0x8008_1272;
pub(super) const INT_BYTES: u64 = 4;
pub(super) const LOFF_BYTES: u64 = 8;
pub(super) const PAGE_BYTES: u64 = 4096;

pub(super) const FSXATTR_BYTES: u64 = 28;
pub(super) const FSUUID2_BYTES: u64 = 17;
pub(super) const EXT4_LABEL_MAX: usize = 16;
pub(super) const EXT4_LABEL_BYTES: u64 = 17;
pub(super) const FILE_CLONE_RANGE_BYTES: u64 = 32;
pub(super) const DEDUPE_RANGE_BYTES: u64 = 24;
pub(super) const DEDUPE_INFO_BYTES: u64 = 32;
pub(super) const DEDUPE_SRC_OFFSET: u64 = 0;
pub(super) const DEDUPE_SRC_LENGTH: u64 = 8;
pub(super) const DEDUPE_DEST_COUNT: u64 = 16;
pub(super) const DEDUPE_RESERVED1: u64 = 18;
pub(super) const DEDUPE_RESERVED2: u64 = 20;
pub(super) const DEDUPE_INFO_DEST_FD: u64 = 0;
pub(super) const DEDUPE_INFO_DEST_OFFSET: u64 = 8;
pub(super) const DEDUPE_INFO_BYTES_DEDUPED: u64 = 16;
pub(super) const DEDUPE_INFO_STATUS: u64 = 24;
pub(super) const DEDUPE_INFO_RESERVED: u64 = 28;
pub(super) const SPACE_RESV_BYTES: u64 = 48;
pub(super) const SPACE_RESV_L_WHENCE: u64 = 2;
pub(super) const SPACE_RESV_L_START: u64 = 8;
pub(super) const SPACE_RESV_L_LEN: u64 = 16;

pub(super) const FS_IOC_RESVSP: u64 = 0x4030_5828;
pub(super) const FS_IOC_UNRESVSP: u64 = 0x4030_5829;
pub(super) const FS_IOC_RESVSP64: u64 = 0x4030_582A;
pub(super) const FS_IOC_UNRESVSP64: u64 = 0x4030_582B;
pub(super) const FS_IOC_ZERO_RANGE: u64 = 0x4030_5839;
pub(super) const FS_IOC_GETFLAGS: u64 = 0x8008_6601;
pub(super) const FS_IOC_SETFLAGS: u64 = 0x4008_6602;
pub(super) const FS_IOC_GETVERSION: u64 = 0x8008_7601;
pub(super) const FS_IOC_SETVERSION: u64 = 0x4008_7602;
pub(super) const EXT4_IOC_GETVERSION: u64 = 0x8008_6603;
pub(super) const EXT4_IOC_SETVERSION: u64 = 0x4008_6604;
pub(super) const FS_IOC_FSGETXATTR: u64 = 0x801C_581F;
pub(super) const FS_IOC_FSSETXATTR: u64 = 0x401C_5820;
pub(super) const FS_IOC_GETFSUUID: u64 = 0x8011_1500;
pub(super) const FS_IOC_GETFSSYSFSPATH: u64 = 0x8081_1501;
pub(super) const FS_IOC_GETFSLABEL: u64 = 0x8100_9431;
pub(super) const FS_IOC_SETFSLABEL: u64 = 0x4100_9432;
pub(super) const FITRIM: u64 = 0xC018_5879;
pub(super) const FSTRIM_RANGE_BYTES: u64 = 24;
pub(super) const FS_SYSFS_PATH_BYTES: u64 = 129;
pub(super) const FS_SYSFS_PATH_NAME_BYTES: usize = 128;

pub(super) const SEEK_SET: i16 = 0;
pub(super) const SEEK_CUR: i16 = 1;
pub(super) const SEEK_END: i16 = 2;
pub(super) const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
pub(super) const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
pub(super) const REMAP_FILE_DEDUP: u32 = 1;
pub(super) const REMAP_FILE_CAN_SHORTEN: u32 = 2;
pub(super) const FILE_DEDUPE_RANGE_SAME: i32 = 0;
pub(super) const FILE_DEDUPE_RANGE_DIFFERS: i32 = 1;

pub(super) const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub(super) const FS_APPEND_FL: u32 = 0x0000_0020;
pub(super) const FS_SYNC_FL: u32 = 0x0000_0008;
pub(super) const FS_NOATIME_FL: u32 = 0x0000_0080;
pub(super) const FS_NODUMP_FL: u32 = 0x0000_0040;
pub(super) const FS_PROJINHERIT_FL: u32 = 0x2000_0000;
pub(super) const FS_VERITY_FL: u32 = 0x0010_0000;
pub(super) const FS_DAX_FL: u32 = 0x0200_0000;
pub(super) const FS_CASEFOLD_FL: u32 = 0x4000_0000;

pub(super) const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
pub(super) const FS_XFLAG_APPEND: u32 = 0x0000_0010;
pub(super) const FS_XFLAG_SYNC: u32 = 0x0000_0020;
pub(super) const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
pub(super) const FS_XFLAG_NODUMP: u32 = 0x0000_0080;
pub(super) const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;
pub(super) const FS_XFLAG_DAX: u32 = 0x0000_8000;
pub(super) const FS_XFLAG_VERITY: u32 = 0x0002_0000;
pub(super) const FS_XFLAG_PREALLOC: u32 = 0x0000_0002;
pub(super) const FS_XFLAG_CASEFOLD: u32 = 0x0004_0000;
pub(super) const FS_XFLAG_CASENONPRESERVING: u32 = 0x0008_0000;
pub(super) const FS_XFLAG_HASATTR: u32 = 0x8000_0000;
pub(super) const FS_XFLAG_EXTSIZE: u32 = 0x0000_0800;
pub(super) const FS_XFLAG_COWEXTSIZE: u32 = 0x0001_0000;
pub(super) const FS_XFLAG_RTINHERIT: u32 = 0x0000_0100;
pub(super) const FS_XFLAG_NOSYMLINKS: u32 = 0x0000_0400;
pub(super) const FS_XFLAG_EXTSZINHERIT: u32 = 0x0000_1000;
pub(super) const FS_XFLAG_REALTIME: u32 = 0x0000_0001;
pub(super) const FS_XFLAG_NODEFRAG: u32 = 0x0000_2000;
pub(super) const FS_XFLAG_FILESTREAM: u32 = 0x0000_4000;
pub(super) const FS_XFLAG_COMMON: u32 = FS_XFLAG_SYNC | FS_XFLAG_IMMUTABLE | FS_XFLAG_APPEND
    | FS_XFLAG_NODUMP | FS_XFLAG_NOATIME | FS_XFLAG_DAX | FS_XFLAG_PROJINHERIT
    | FS_XFLAG_VERITY;
pub(super) const FS_XFLAG_RDONLY_MASK: u32 = FS_XFLAG_PREALLOC | FS_XFLAG_HASATTR | FS_XFLAG_VERITY
    | FS_XFLAG_CASEFOLD | FS_XFLAG_CASENONPRESERVING;
pub(super) const FS_XFLAGS_MASK: u32 = FS_XFLAG_COMMON | FS_XFLAG_RDONLY_MASK | FS_XFLAG_EXTSIZE
    | FS_XFLAG_COWEXTSIZE | FS_XFLAG_RTINHERIT | FS_XFLAG_NOSYMLINKS | FS_XFLAG_EXTSZINHERIT
    | FS_XFLAG_REALTIME | FS_XFLAG_NODEFRAG | FS_XFLAG_FILESTREAM;
