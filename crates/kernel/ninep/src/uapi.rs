// 9P wire constants. Numbers only — no policy, no logic (`52§5`).
// Every value here is fixed by the 9P2000 / 9P2000.u / 9P2000.L protocol
// definition and is re-checked by the round-trip tests in `tests/`.

/// Message opcodes. `R<op> == T<op> + 1` for every pair; the codec relies on
/// that identity to derive an expected reply type from a request type.
pub mod op {
    /// 9P2000.L error reply (numeric errno). No matching T-message exists.
    pub const RLERROR: u8 = 7;
    pub const TSTATFS: u8 = 8;
    pub const TLOPEN: u8 = 12;
    pub const TLCREATE: u8 = 14;
    pub const TSYMLINK: u8 = 16;
    pub const TMKNOD: u8 = 18;
    pub const TRENAME: u8 = 20;
    pub const TREADLINK: u8 = 22;
    pub const TGETATTR: u8 = 24;
    pub const TSETATTR: u8 = 26;
    pub const TXATTRWALK: u8 = 30;
    pub const TXATTRCREATE: u8 = 32;
    pub const TREADDIR: u8 = 40;
    pub const TFSYNC: u8 = 50;
    pub const TLOCK: u8 = 52;
    pub const TGETLOCK: u8 = 54;
    pub const TLINK: u8 = 70;
    pub const TMKDIR: u8 = 72;
    pub const TRENAMEAT: u8 = 74;
    pub const TUNLINKAT: u8 = 76;
    pub const TVERSION: u8 = 100;
    pub const TAUTH: u8 = 102;
    pub const TATTACH: u8 = 104;
    /// Legacy (9P2000 / 9P2000.u) error reply carrying a string. No T-message.
    pub const RERROR: u8 = 107;
    pub const TFLUSH: u8 = 108;
    pub const TWALK: u8 = 110;
    pub const TOPEN: u8 = 112;
    pub const TCREATE: u8 = 114;
    pub const TREAD: u8 = 116;
    pub const TWRITE: u8 = 118;
    pub const TCLUNK: u8 = 120;
    pub const TREMOVE: u8 = 122;
    pub const TSTAT: u8 = 124;
    pub const TWSTAT: u8 = 126;

    /// Reply opcode paired with request `t`. # C: O(1)
    pub const fn reply_of(t: u8) -> u8 { t + 1 }
}

/// Header and framing sizes.
pub mod limits {
    /// `size[4] type[1] tag[2]` — every message begins with these 7 bytes.
    pub const HDRSZ: usize = 7;
    /// Headroom a `Twrite`/`Rread` header needs on top of the payload.
    pub const IOHDRSZ: usize = 24;
    /// Headroom an `Rreaddir` header needs on top of the entry bytes.
    pub const READDIRHDRSZ: usize = 24;
    /// Longest error string a legacy `Rerror` may carry.
    pub const ERRMAX: usize = 128;
    /// Maximum path elements one `Twalk` may carry; a longer walk is chunked.
    pub const MAXWELEM: usize = 16;
    /// Reserved tag used by `Tversion`, which precedes tag allocation.
    pub const NOTAG: u16 = u16::MAX;
    /// Reserved fid meaning "no fid" (`Tattach` afid, `Twalk` from nothing).
    pub const NOFID: u32 = u32::MAX;
    /// Default negotiated `msize` when the mount does not name one: a 128 KiB
    /// payload PLUS the I/O envelope, so a full-size read is not one byte short
    /// of a round number and forced into a second round trip.
    pub const DEFAULT_MSIZE: u32 = 128 * 1024 + IOHDRSZ as u32;
    /// Smallest `msize` accepted from either side. A mount asking for less is
    /// refused, and a server answering with less fails the handshake — it is
    /// not silently raised, because the peer would then frame to its own value.
    pub const MIN_MSIZE: u32 = 4096;
    /// Largest `msize` a byte-stream transport will negotiate.
    pub const MAX_SOCK_MSIZE: u32 = 1024 * 1024;
    /// Scatter-gather entries one virtio 9P request may occupy.
    pub const VIRTQUEUE_NUM: usize = 128;
    /// Descriptors the virtio transport reserves out of `VIRTQUEUE_NUM`: one
    /// for the request header run, one for the reply header, and one for a
    /// payload whose start is not page-aligned and therefore spills a page.
    pub const VIRTIO_RESERVED_DESCS: usize = 3;
    /// Largest `msize` the virtio transport can frame for a given page size.
    /// # C: O(1)
    pub const fn virtio_max_msize(page_size: usize) -> u32 {
        (page_size * (VIRTQUEUE_NUM - VIRTIO_RESERVED_DESCS)) as u32
    }
    /// Default TCP port a `trans=tcp` mount connects to.
    pub const FD_PORT: u16 = 564;
    /// Lowest port a `privport` mount binds its local end to.
    pub const MIN_RESVPORT: u16 = 665;
    /// Highest port a `privport` mount binds its local end to.
    pub const MAX_RESVPORT: u16 = 1023;
    /// Encoded width of a `qid` on the wire: type[1] version[4] path[8].
    pub const QID_SZ: usize = 13;
    /// Encoded width of a fixed `Rgetattr` body after the header.
    pub const GETATTR_BODY_SZ: usize = 8 + QID_SZ + 4 + 4 + 4 + 8 * 15;
    /// Encoded width of a `Tsetattr` body after `fid[4]`:
    /// valid[4] mode[4] uid[4] gid[4] size[8] atime[8+8] mtime[8+8].
    pub const SETATTR_BODY_SZ: usize = 4 + 4 + 4 + 4 + 8 * 5;
    /// Encoded width of an `Rstatfs` body after the header.
    pub const STATFS_BODY_SZ: usize = 4 + 4 + 8 * 6 + 4;
    /// Fixed prefix of one `.L` readdir entry: qid[13] offset[8] type[1].
    pub const DIRENT_FIXED_SZ: usize = QID_SZ + 8 + 1;
}

/// Protocol version strings offered in `Tversion`.
pub mod version {
    /// The Linux dialect: numeric errnos, POSIX metadata, `Treaddir`.
    pub const V9P2000L: &str = "9P2000.L";
    /// The Unix extension dialect: string errnos plus numeric uid/gid.
    pub const V9P2000U: &str = "9P2000.u";
    /// Base Plan 9 protocol: string errnos, `Tstat`-based metadata.
    pub const V9P2000: &str = "9P2000";
    /// Reply a server sends when it recognises no offered version.
    pub const UNKNOWN: &str = "unknown";
}

/// `qid.type` bits — the entity class a server reports for a path.
pub mod qid {
    pub const QTDIR: u8 = 0x80;
    pub const QTAPPEND: u8 = 0x40;
    pub const QTEXCL: u8 = 0x20;
    pub const QTMOUNT: u8 = 0x10;
    pub const QTAUTH: u8 = 0x08;
    pub const QTTMP: u8 = 0x04;
    pub const QTSYMLINK: u8 = 0x02;
    pub const QTLINK: u8 = 0x01;
    pub const QTFILE: u8 = 0x00;
}

/// Plan 9 `stat.mode` bits (the high half of the permission word).
pub mod dm {
    pub const DMDIR: u32 = 0x8000_0000;
    pub const DMAPPEND: u32 = 0x4000_0000;
    pub const DMEXCL: u32 = 0x2000_0000;
    pub const DMMOUNT: u32 = 0x1000_0000;
    pub const DMAUTH: u32 = 0x0800_0000;
    pub const DMTMP: u32 = 0x0400_0000;
    pub const DMSYMLINK: u32 = 0x0200_0000;
    pub const DMLINK: u32 = 0x0100_0000;
    pub const DMDEVICE: u32 = 0x0080_0000;
    pub const DMNAMEDPIPE: u32 = 0x0020_0000;
    pub const DMSOCKET: u32 = 0x0010_0000;
    pub const DMSETUID: u32 = 0x0008_0000;
    pub const DMSETGID: u32 = 0x0004_0000;
    pub const DMSETVTX: u32 = 0x0001_0000;
    /// Permission bits below the type/attribute half.
    pub const PERM_MASK: u32 = 0o777;
}

/// Legacy `Topen`/`Tcreate` mode byte (9P2000, not the `.L` flag word).
pub mod omode {
    pub const OREAD: u8 = 0x00;
    pub const OWRITE: u8 = 0x01;
    pub const ORDWR: u8 = 0x02;
    pub const OEXEC: u8 = 0x03;
    pub const OTRUNC: u8 = 0x10;
    pub const OREXEC: u8 = 0x20;
    pub const ORCLOSE: u8 = 0x40;
    pub const OAPPEND: u8 = 0x80;
    /// Access-mode field of the mode byte.
    pub const ACCESS_MASK: u8 = 0x03;
}

/// `.L` open/create flag word — the protocol's own numbering, deliberately
/// re-declared rather than reusing a host `O_*` value.
pub mod dotl {
    pub const RDONLY: u32 = 0o0;
    pub const WRONLY: u32 = 0o1;
    pub const RDWR: u32 = 0o2;
    pub const NOACCESS: u32 = 0o3;
    pub const CREATE: u32 = 0o100;
    pub const EXCL: u32 = 0o200;
    pub const NOCTTY: u32 = 0o400;
    pub const TRUNC: u32 = 0o1000;
    pub const APPEND: u32 = 0o2000;
    pub const NONBLOCK: u32 = 0o4000;
    pub const DSYNC: u32 = 0o10000;
    pub const FASYNC: u32 = 0o20000;
    pub const DIRECT: u32 = 0o40000;
    pub const LARGEFILE: u32 = 0o100000;
    pub const DIRECTORY: u32 = 0o200000;
    pub const NOFOLLOW: u32 = 0o400000;
    pub const NOATIME: u32 = 0o1000000;
    pub const CLOEXEC: u32 = 0o2000000;
    pub const SYNC: u32 = 0o4000000;
    /// Access-mode field of the `.L` flag word.
    pub const ACCESS_MASK: u32 = 0o3;
    /// `Tunlinkat` flag selecting directory removal.
    pub const AT_REMOVEDIR: u32 = 0x200;
}

/// `Tgetattr` request mask / `Rgetattr` valid mask bits.
pub mod stats {
    pub const MODE: u64 = 0x0000_0001;
    pub const NLINK: u64 = 0x0000_0002;
    pub const UID: u64 = 0x0000_0004;
    pub const GID: u64 = 0x0000_0008;
    pub const RDEV: u64 = 0x0000_0010;
    pub const ATIME: u64 = 0x0000_0020;
    pub const MTIME: u64 = 0x0000_0040;
    pub const CTIME: u64 = 0x0000_0080;
    pub const INO: u64 = 0x0000_0100;
    pub const SIZE: u64 = 0x0000_0200;
    pub const BLOCKS: u64 = 0x0000_0400;
    pub const BTIME: u64 = 0x0000_0800;
    pub const GEN: u64 = 0x0000_1000;
    pub const DATA_VERSION: u64 = 0x0000_2000;
    /// Fields a `stat(2)` needs — everything up to and including BLOCKS.
    pub const BASIC: u64 = 0x0000_07ff;
    /// Every defined field.
    pub const ALL: u64 = 0x0000_3fff;
}

/// `Tsetattr` valid-field bits.
pub mod setattr {
    pub const MODE: u32 = 0x0000_0001;
    pub const UID: u32 = 0x0000_0002;
    pub const GID: u32 = 0x0000_0004;
    pub const SIZE: u32 = 0x0000_0008;
    pub const ATIME: u32 = 0x0000_0010;
    pub const MTIME: u32 = 0x0000_0020;
    pub const CTIME: u32 = 0x0000_0040;
    /// Set atime to the value supplied rather than to "now".
    pub const ATIME_SET: u32 = 0x0000_0080;
    /// Set mtime to the value supplied rather than to "now".
    pub const MTIME_SET: u32 = 0x0000_0100;
}

/// `Tlock`/`Tgetlock` types, flags and result codes.
pub mod lock {
    pub const TYPE_RDLCK: u8 = 0;
    pub const TYPE_WRLCK: u8 = 1;
    pub const TYPE_UNLCK: u8 = 2;
    pub const FLAGS_BLOCK: u32 = 1;
    pub const FLAGS_RECLAIM: u32 = 2;
    pub const SUCCESS: u8 = 0;
    pub const BLOCKED: u8 = 1;
    pub const ERROR: u8 = 2;
    pub const GRACE: u8 = 3;
}
