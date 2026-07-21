// VFS shared types per `16§2` and `15§6.1` / `15§6.4`.

extern crate alloc;

/// Inode number per `01§4`.
pub type Ino = u64;

/// Linux `mode_t` (POSIX bits). Layout in `15§6.4`.
pub type FileMode = u32;

/// File-type tag — high nibble of `FileMode` shapes this in POSIX, but
/// VFS callers use the typed enum to avoid bit-twiddling.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    CharDev,
    BlockDev,
    Fifo,
    Socket,
}

/// Linux `umode_t` — the unified mode word: `S_IFMT` type bits OR'd with the
/// low-12 permission/setid/sticky bits. This is `i_mode` in Linux `struct
/// inode`; the VFS `FileType` enum + `Inode::perm()` are its internal split.
/// `Inode::i_mode()` (inode.rs) reassembles the umode_t view.
pub type Umode = u16;

/// `S_IF*` file-type bits (Linux `include/uapi/linux/stat.h`), canonical typed
/// `Umode` defs for the whole vfs crate. The `u32` `Kstat`/ABI surface in
/// `getattr` re-derives from these (single source of truth, no magic literals).
pub const S_IFMT:   Umode = 0o170000;
pub const S_IFSOCK: Umode = 0o140000;
pub const S_IFLNK:  Umode = 0o120000;
pub const S_IFREG:  Umode = 0o100000;
pub const S_IFBLK:  Umode = 0o060000;
pub const S_IFDIR:  Umode = 0o040000;
pub const S_IFCHR:  Umode = 0o020000;
pub const S_IFIFO:  Umode = 0o010000;

/// Set-uid / set-gid / sticky bits (Linux `S_ISUID`/`S_ISGID`/`S_ISVTX`).
/// `S_ISUID`/`S_ISGID` canonical defs live in `namei` (their consumer = the
/// chown/chmod privilege-kill logic) and are re-exported there; `S_ISVTX`
/// (sticky) is defined here. All three are `Umode`.
pub const S_ISVTX: Umode = 0o1000;

impl FileType {
    /// `S_IFMT` type bits for this file type — the high half of the Linux
    /// `umode_t`/`i_mode` word. Inverse of `i_mode & S_IFMT`. # C: O(1)
    pub fn to_ifmt(&self) -> Umode {
        match self {
            FileType::Socket    => S_IFSOCK,
            FileType::Symlink   => S_IFLNK,
            FileType::Regular   => S_IFREG,
            FileType::BlockDev  => S_IFBLK,
            FileType::Directory => S_IFDIR,
            FileType::CharDev   => S_IFCHR,
            FileType::Fifo      => S_IFIFO,
        }
    }

    /// Inverse of [`Self::to_ifmt`] — classify the `S_IFMT` half of a `umode_t`
    /// (Linux `inode->i_mode & S_IFMT`). An unrecognised type-nibble defaults to
    /// `Regular` (Linux treats a zero/garbage `S_IFMT` as a regular file for
    /// `i_op`/`i_fop` binding). # C: O(1)
    pub fn from_ifmt(mode: Umode) -> FileType {
        match mode & S_IFMT {
            S_IFSOCK => FileType::Socket,
            S_IFLNK  => FileType::Symlink,
            S_IFBLK  => FileType::BlockDev,
            S_IFDIR  => FileType::Directory,
            S_IFCHR  => FileType::CharDev,
            S_IFIFO  => FileType::Fifo,
            _        => FileType::Regular,
        }
    }
}

bitflags::bitflags! {
    /// `open(2)` flag bits per `15§6.1`. Numeric values match Linux
    /// x86_64 exactly. Subset for v1; expand alongside their first
    /// real consumer.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct OpenFlags: u32 {
        const O_RDONLY    = 0;
        const O_WRONLY    = 1;
        const O_RDWR      = 2;
        const O_CREAT     = 0o100;
        const O_EXCL      = 0o200;
        const O_TRUNC     = 0o1000;
        const O_APPEND    = 0o2000;
        const O_NONBLOCK  = 0o4000;
        const O_DIRECTORY = 0o200000;
        const O_NOFOLLOW  = 0o400000;
        const O_CLOEXEC   = 0o2000000;
        // D22: status / open-time bits with no VFS data-path consumer YET, but
        // declared so the typed set is the single source of truth and
        // `from_bits_truncate` no longer SILENTLY STRIPS them off the open word
        // (Linux keeps them in `f_flags`). Values = x86_64 / asm-generic uapi
        // (`include/uapi/asm-generic/fcntl.h`); aarch64 shares them.
        /// `O_NOCTTY` — don't make this terminal the process's controlling tty.
        const O_NOCTTY    = 0o400;
        /// `O_DSYNC` — synchronised I/O data integrity (data + size metadata).
        const O_DSYNC     = 0o10000;
        /// `O_DIRECT` — minimise page-cache buffering for this fd.
        const O_DIRECT    = 0o40000;
        /// `O_LARGEFILE` — allow >2 GiB offsets (kernel-implicit on 64-bit).
        const O_LARGEFILE = 0o100000;
        /// `O_NOATIME` — don't update `i_atime` on read through this fd.
        const O_NOATIME   = 0o1000000;
        /// `O_SYNC` — synchronised I/O file integrity (`__O_SYNC | O_DSYNC`).
        const O_SYNC      = 0o4010000;
        /// `O_PATH` — fd-reference only (no read/write; resolves the path).
        const O_PATH      = 0o10000000;
        /// `O_TMPFILE` — create an unnamed temp inode (`__O_TMPFILE |
        /// O_DIRECTORY`); the dir operand names the host directory.
        const O_TMPFILE   = 0o20200000;
    }
}

bitflags::bitflags! {
    /// `statx` request-mask bits per `15§6` (subset).
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct StatxMask: u32 {
        const TYPE   = 1 << 0;
        const MODE   = 1 << 1;
        const NLINK  = 1 << 2;
        const UID    = 1 << 3;
        const GID    = 1 << 4;
        const ATIME  = 1 << 5;
        const MTIME  = 1 << 6;
        const CTIME  = 1 << 7;
        const INO    = 1 << 8;
        const SIZE   = 1 << 9;
        const BLOCKS = 1 << 10;
        const BTIME  = 1 << 11;
    }
}

bitflags::bitflags! {
    /// `poll` event-mask bits per `15§2`.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct PollMask: u32 {
        const POLLIN     = 0x0001;
        const POLLOUT    = 0x0004;
        const POLLERR    = 0x0008;
        const POLLHUP    = 0x0010;
        const POLLPRI    = 0x0002;
        const POLLRDHUP  = 0x2000;
    }
}

/// VFS-level error type. Numeric values align with `crates/syscall::Errno`
/// so the dispatch path can encode them directly without translation.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VfsError {
    Eperm   = 1,
    Enoent  = 2,
    Esrch   = 3,
    Eintr   = 4,
    Eio     = 5,
    /// ENXIO — `open(2)` of a device node whose `(major,minor)` has no
    /// registered driver (Linux `chrdev_open`/`blkdev_open` miss).
    Enxio   = 6,
    Ebadf   = 9,
    Enomem  = 12,
    Eacces  = 13,
    Efault  = 14,
    Enotblk = 15,
    Eexist  = 17,
    Exdev   = 18,
    /// ENODEV — operation on a node whose device class is unknown.
    Enodev  = 19,
    Enotdir = 20,
    Eisdir  = 21,
    Einval  = 22,
    Emfile  = 24,
    Enotty  = 25,
    Etxtbsy = 26,
    Efbig   = 27,
    Espipe  = 29,
    Emlink  = 31,
    Eagain  = 11,
    Epipe   = 32,
    Erange  = 34,
    Erofs   = 30,
    Ebusy   = 16,
    Enospc  = 28,
    Enotempty = 39,
    Enosys  = 38,
    Eloop   = 40,
    Ebade   = 52,
    Enodata = 61,
    Enonet  = 64,
    Emsgsize = 90,
    Enoprotoopt = 92,
    Eproto  = 71,
    Ehostdown = 112,
    Eopnotsupp = 95,
    Edestaddrreq = 89,
    Eaddrnotavail = 99,
    Enetunreach = 101,
    Ehostunreach = 113,
    Enobufs  = 105,
    Enametoolong = 36,
    /// ENOTCONN — read/write on a stream socket with no connection.
    Enotconn = 107,
    Econnaborted = 103,
    Econnreset = 104,
    Etimedout = 110,
    Econnrefused = 111,
    /// EUCLEAN — filesystem metadata is structurally corrupt.
    Euclean = 117,
    /// ECANCELED — timerfd read after TFD_TIMER_CANCEL_ON_SET clock change.
    Ecanceled = 125,
    /// EDQUOT — quota hard limit exceeded.
    Edquot  = 122,
}

pub type KResult<T> = core::result::Result<T, VfsError>;
