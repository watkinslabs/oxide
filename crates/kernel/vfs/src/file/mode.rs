use crate::types::OpenFlags;

/// Lock class for `File::f_pos_lock` (`06§3.6`). Ranked below `Inode`
/// (40): the pos lock is acquired in `read`/`write` BEFORE the inode I/O
/// that takes the inode lock, mirroring Linux `__fdget_pos` preceding
/// `vfs_read`/`vfs_write`. Defined locally (not in the shared `sync`
/// taxonomy) so this change stays self-contained.
pub(crate) struct FilePos;
impl sync::LockClass for FilePos {
    /// # C: O(1)
    fn rank() -> u16 { 35 }
}

bitflags::bitflags! {
    /// `file->f_mode` access bits (Linux `include/linux/fs.h` `FMODE_*`).
    /// Derived once from the open access mode at `File` construction so
    /// permission checks read the canonical capability rather than
    /// re-deriving from `O_*` flags at each call. Numeric values match
    /// Linux exactly.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct Fmode: u32 {
        /// FMODE_READ — file is readable.
        const READ   = 0x0000_0001;
        /// FMODE_WRITE — file is writable.
        const WRITE  = 0x0000_0002;
        /// FMODE_LSEEK — file is seekable (`do_dentry_open`: `f_op->llseek`
        /// present and not `no_llseek`). Gates `lseek(2)`.
        const LSEEK  = 0x0000_0004;
        /// FMODE_PREAD — positional read supported (`f_op->read_iter`). Gates
        /// `pread(2)`.
        const PREAD  = 0x0000_0008;
        /// FMODE_PWRITE — positional write supported (`f_op->write_iter`).
        /// Gates `pwrite(2)`.
        const PWRITE = 0x0000_0010;
        /// FMODE_EXEC — opened for execution (`do_open_execat`).
        const EXEC   = 0x0000_0020;
        /// FMODE_PATH — O_PATH descriptor (no read/write, fd-ref only).
        const PATH   = 0x0000_4000;
        /// FMODE_OPENED — `do_dentry_open` reached the point past `f_op->open`
        /// (the description is fully opened). Linux `(1 << 19)`.
        const OPENED  = 0x0008_0000;
        /// FMODE_CREATED — this open CREATED the file (`O_CREAT` hit the
        /// negative-dentry path), distinguishing create-vs-existing for events
        /// / audit after the open returns. Linux `(1 << 20)`.
        const CREATED = 0x0010_0000;
        /// FMODE_NONOTIFY — suppress fsnotify events on this description
        /// (fanotify's own fds avoid self-notification loops). Linux `(1 << 26)`.
        const NONOTIFY = 0x0400_0000;
    }
}

/// `O_DIRECT` (asm-generic, 0o40000) and `O_NOATIME` (0o1000000) — settable
/// via `F_SETFL` but not declared in `OpenFlags` (no in-`vfs` consumer yet),
/// so they're matched here by raw value so the mask can preserve/update them
/// exactly like Linux. `O_NDELAY` aliases `O_NONBLOCK` on both arches.
pub(crate) const O_DIRECT:  u32 = 0o40000;
pub(crate) const O_NOATIME: u32 = 0o1000000;

/// `O_ASYNC`/`FASYNC` (asm-generic, both arches — Linux `fcntl.h` `0o20000`).
/// Settable via `F_SETFL`; toggling it (de)registers the open file description
/// for fasync SIGIO/SIGURG delivery to its `f_owner` (Linux `setfl`'s
/// `FASYNC` branch calling `f_op->fasync`). Not declared in `OpenFlags` (no
/// other in-`vfs` consumer), so matched here by raw value, and the stored bit
/// is read by `File::is_async`.
pub(crate) const O_ASYNC: u32 = 0o20000;

/// Linux `SETFL_MASK` (`fs/fcntl.c`): the only `f_flags` bits `fcntl(F_SETFL)`
/// may change on an already-open file description. The access mode
/// (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) and the creation-time flags
/// (`O_CREAT`/`O_EXCL`/`O_TRUNC`/`O_CLOEXEC`/`O_DIRECTORY`/…) are fixed at open
/// and silently ignored by `F_SETFL`, so they are excluded here.
pub(crate) const SETFL_MASK: u32 =
    OpenFlags::O_APPEND.bits() | OpenFlags::O_NONBLOCK.bits() | O_DIRECT | O_NOATIME | O_ASYNC;

/// Map an open's access mode (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) to the
/// canonical `Fmode` capability bits. Mirrors Linux `OPEN_FMODE`. An `O_PATH`
/// open yields `FMODE_PATH` only (no read/write) regardless of the access-mode
/// bits, matching Linux `do_dentry_open`. `O_PATH` is a declared `OpenFlags`
/// bit (single source of truth, `types.rs`), so the open path's
/// `from_bits_truncate(flags)` preserves it through to here — it is no longer
/// silently stripped (Linux keeps it in `f_flags`).
/// # C: O(1)
pub(crate) fn fmode_from_flags(f: OpenFlags) -> Fmode {
    if f.contains(OpenFlags::O_PATH) {
        return Fmode::PATH; // fd-reference only: no READ, no WRITE
    }
    let mut m = Fmode::empty();
    if f.contains(OpenFlags::O_RDWR) {
        m |= Fmode::READ | Fmode::WRITE;
    } else if f.contains(OpenFlags::O_WRONLY) {
        m |= Fmode::WRITE;
    } else {
        m |= Fmode::READ; // O_RDONLY (access mode 0)
    }
    m
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SeekFrom {
    /// `SEEK_SET` — base 0; the `off` arg is the absolute position.
    Start,
    /// `SEEK_CUR` — base the current cursor.
    Current,
    /// `SEEK_END` — base `i_size`.
    End,
    /// `SEEK_DATA` (whence 3) — the `off` arg is the start byte; resolve to the
    /// next data byte via `f_op->seek_hole_data`.
    Data,
    /// `SEEK_HOLE` (whence 4) — the `off` arg is the start byte; resolve to the
    /// next hole via `f_op->seek_hole_data`.
    Hole,
}
