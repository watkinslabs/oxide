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
pub const FS_VERITY_FL:    u32 = 0x0010_0000;
pub const FS_DAX_FL:       u32 = 0x0200_0000;
pub const FS_PROJINHERIT_FL: u32 = 0x2000_0000;
pub const FS_CASEFOLD_FL:  u32 = 0x4000_0000;
pub const FS_COMMON_FL:    u32 = FS_SYNC_FL | FS_IMMUTABLE_FL | FS_APPEND_FL
    | FS_NODUMP_FL | FS_NOATIME_FL | FS_DAX_FL | FS_PROJINHERIT_FL | FS_VERITY_FL;

/// `FS_XFLAG_*` — the whole published set, so no caller
/// re-declares a subset of its own.
pub const FS_XFLAG_REALTIME:  u32 = 0x0000_0001;
pub const FS_XFLAG_PREALLOC:  u32 = 0x0000_0002;
pub const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
pub const FS_XFLAG_APPEND:    u32 = 0x0000_0010;
pub const FS_XFLAG_SYNC:      u32 = 0x0000_0020;
pub const FS_XFLAG_NOATIME:   u32 = 0x0000_0040;
pub const FS_XFLAG_NODUMP:    u32 = 0x0000_0080;
pub const FS_XFLAG_RTINHERIT: u32 = 0x0000_0100;
pub const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;
pub const FS_XFLAG_NOSYMLINKS: u32 = 0x0000_0400;
pub const FS_XFLAG_EXTSIZE:   u32 = 0x0000_0800;
pub const FS_XFLAG_EXTSZINHERIT: u32 = 0x0000_1000;
pub const FS_XFLAG_NODEFRAG:  u32 = 0x0000_2000;
pub const FS_XFLAG_FILESTREAM: u32 = 0x0000_4000;
pub const FS_XFLAG_DAX:       u32 = 0x0000_8000;
pub const FS_XFLAG_COWEXTSIZE: u32 = 0x0001_0000;
pub const FS_XFLAG_VERITY:    u32 = 0x0002_0000;
pub const FS_XFLAG_CASEFOLD:  u32 = 0x0004_0000;
pub const FS_XFLAG_CASENONPRESERVING: u32 = 0x0008_0000;
pub const FS_XFLAG_HASATTR:   u32 = 0x8000_0000;

/// `FS_XFLAG_*` masks — shared between `flags` and `xflags`,
/// read-only, value-carrying, directory-only, and misc-settable.
pub const FS_XFLAG_COMMON:    u32 = FS_XFLAG_SYNC | FS_XFLAG_IMMUTABLE | FS_XFLAG_APPEND
    | FS_XFLAG_NODUMP | FS_XFLAG_NOATIME | FS_XFLAG_DAX | FS_XFLAG_PROJINHERIT | FS_XFLAG_VERITY;
pub const FS_XFLAG_RDONLY_MASK: u32 = FS_XFLAG_PREALLOC | FS_XFLAG_HASATTR | FS_XFLAG_VERITY
    | FS_XFLAG_CASEFOLD | FS_XFLAG_CASENONPRESERVING;
pub const FS_XFLAG_VALUES_MASK: u32 = FS_XFLAG_EXTSIZE | FS_XFLAG_COWEXTSIZE;
pub const FS_XFLAG_DIRONLY_MASK: u32 = FS_XFLAG_RTINHERIT | FS_XFLAG_NOSYMLINKS
    | FS_XFLAG_EXTSZINHERIT;
pub const FS_XFLAG_MISC_MASK: u32 = FS_XFLAG_REALTIME | FS_XFLAG_NODEFRAG | FS_XFLAG_FILESTREAM;
pub const FS_XFLAGS_MASK:     u32 = FS_XFLAG_COMMON | FS_XFLAG_RDONLY_MASK | FS_XFLAG_VALUES_MASK
    | FS_XFLAG_DIRONLY_MASK | FS_XFLAG_MISC_MASK;

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
pub const I_LINKABLE:       u32 = 1 << 7;
/// `I_DIRTY_TIME` — the inode's OWN timestamps differ from the on-disk copy and
/// the superblock is mounted `lazytime`, so the difference is deliberately not
/// yet persisted. Tracked apart from `I_DIRTY_SYNC` because that is the whole of
/// lazytime: a pure timestamp change costs no I/O until a forcing point
/// (`fsync`/`sync`/`syncfs`, an unrelated inode change, eviction of a linked
/// inode, unmount, or the expiry interval) converts it. `I_DIRTY_INODE`
/// supersedes it — a real metadata change writes the timestamps out with itself
/// — but it may be re-set over an `I_DIRTY_SYNC` already in flight so a
/// concurrent writeback cannot swallow a newer stamp.
pub const I_DIRTY_TIME:     u32 = 1 << 8;
/// The inode ITSELF is dirty (as opposed to only its pages) — the set that makes
/// `s_op->write_inode` necessary.
pub const I_DIRTY_INODE:    u32 = I_DIRTY_SYNC | I_DIRTY_DATASYNC;
pub const I_DIRTY:          u32 = I_DIRTY_INODE | I_DIRTY_PAGES;
/// Every dirty bit including the lazy-timestamp one — the set that must keep an
/// inode pinned on the writeback list and that eviction has to resolve.
pub const I_DIRTY_ALL:      u32 = I_DIRTY | I_DIRTY_TIME;

pub const S_SYNC:      u32 = 1 << 0;
pub const S_NOATIME:   u32 = 1 << 1;
pub const S_APPEND:    u32 = 1 << 2;
pub const S_IMMUTABLE: u32 = 1 << 3;
pub const S_DEAD:      u32 = 1 << 4;
pub const S_DIRSYNC:   u32 = 1 << 6;
/// `S_SWAPFILE` — swapon captured this inode's block map, so no truncate,
/// fallocate, or remap may move its blocks (Linux `IS_SWAPFILE` → `ETXTBSY`).
pub const S_SWAPFILE:  u32 = 1 << 8;
pub const S_DAX:       u32 = 1 << 13;
pub const S_ENCRYPTED: u32 = 1 << 14;
pub const S_CASEFOLD:  u32 = 1 << 15;
/// `S_ANON_INODE` — this inode came from an `anon_inode_getfd`-style factory
/// (epoll, eventfd, signalfd, timerfd, inotify, fanotify, userfaultfd, perf,
/// io_uring, landlock, bpf). It carries a file type tag for `fstat` but has no
/// filesystem behind it, so the generic `ioctl` owner must not run its
/// regular-file paths on it and must let the fd's own operations answer.
pub const S_ANON_INODE: u32 = 1 << 19;
pub const S_VERITY:    u32 = 1 << 16;
/// oxide-internal `i_flags` bit (like `I_PUBLIC_DEV` in `inode/metadata.rs`).
/// Linux's `inode->i_flags` has no `NODUMP` — `FS_NODUMP_FL` requires no
/// action in `i_flags`, so shmem parks it in a filesystem-private field
/// instead. The oxide inode carries the whole
/// `chattr` word in `i_flags`, so the bit lives here instead of in a
/// per-filesystem shadow field that could disagree with it.
pub const S_NODUMP:    u32 = 1 << 17;

pub const POLL_IN:    u32 = 0x0001;
pub const POLL_OUT:   u32 = 0x0004;
pub const POLL_HUP:   u32 = 0x0010;
pub const POLL_RDNORM: u32 = 0x0040;
/// `EPOLLWRNORM` — the companion of
/// `EPOLLOUT` that every writability wake carries (`sk_stream_write_space`
/// wakes with `EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND`).
pub const POLL_WRNORM: u32 = 0x0100;
pub const POLL_ERR:   u32 = 0x0008;
pub const POLL_PRI:   u32 = 0x0002;
pub const POLL_RDHUP: u32 = 0x2000;
/// `EPOLLRDBAND` — priority-band read data; part of the `POLL_PRI` si_band.
pub const POLL_RDBAND: u32 = 0x0080;
/// `EPOLLWRBAND` — priority-band write room; part of the `POLL_OUT` si_band.
pub const POLL_WRBAND: u32 = 0x0200;
/// `EPOLLMSG` — STREAMS message available; part of the `POLL_MSG` si_band.
pub const POLL_MSG:    u32 = 0x0400;
