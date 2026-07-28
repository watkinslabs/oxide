// `AT_*` dirfd/`*at` flags (`uapi/linux/fcntl.h`). One owner for the ABI
// numbers so a shim, a work-fn crate and a test cannot drift apart on them.

/// `AT_FDCWD` — resolve relative to the calling task's cwd.
pub const AT_FDCWD: i32 = -100;

pub const AT_SYMLINK_NOFOLLOW: u32 = 0x0100;
pub const AT_EACCESS: u32 = 0x0200;
pub const AT_REMOVEDIR: u32 = 0x0200;
pub const AT_SYMLINK_FOLLOW: u32 = 0x0400;
pub const AT_NO_AUTOMOUNT: u32 = 0x0800;
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// The pair every `*at` metadata syscall accepts: operate on the symlink, or
/// on the dirfd itself. Linux `path_setxattrat` / `file_getattr` reject
/// `at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)` with `EINVAL`.
pub const AT_NOFOLLOW_EMPTY: u32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
