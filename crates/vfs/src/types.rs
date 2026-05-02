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
    Eio     = 5,
    Ebadf   = 9,
    Enomem  = 12,
    Eacces  = 13,
    Efault  = 14,
    Eexist  = 17,
    Enotdir = 20,
    Eisdir  = 21,
    Einval  = 22,
    Emfile  = 24,
    Enotty  = 25,
    Espipe  = 29,
    Erofs   = 30,
    Enosys  = 38,
}

pub type KResult<T> = core::result::Result<T, VfsError>;
