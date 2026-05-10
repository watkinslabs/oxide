// Linux-numbered errno per `15§1.3`. Numbers match Linux x86_64
// exactly so libc unwrapping (`-rv` against `4096` threshold) works
// without a translation layer.
//
// Subset for v1 — only the ones the dispatch path and the implemented
// syscalls return. New variants land alongside their first user.

/// Errno values; numeric reps are stable across releases.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Errno {
    Eperm   = 1,
    Enoent  = 2,
    Esrch   = 3,
    Eintr   = 4,
    Eio     = 5,
    Enxio   = 6,
    E2big   = 7,
    Enoexec = 8,
    Ebadf   = 9,
    Echild  = 10,
    Eagain  = 11,
    Enomem  = 12,
    Eacces  = 13,
    Efault  = 14,
    Ebusy   = 16,
    Eexist  = 17,
    Enodev  = 19,
    Enotdir = 20,
    Eisdir  = 21,
    Einval  = 22,
    Enfile  = 23,
    Emfile  = 24,
    Enotty  = 25,
    Espipe  = 29,
    Erofs   = 30,
    Enospc  = 28,
    Epipe   = 32,
    Erange  = 34,
    Enametoolong = 36,
    Enosys  = 38,
    Eidrm   = 43,
    Enomsg  = 42,
    Eopnotsupp        = 95,
    Eafnosupport      = 97,
    Eaddrinuse        = 98,
    Eaddrnotavail     = 99,
    Enetunreach       = 101,
    Enobufs           = 105,
    Enotsock          = 88,
    Edestaddrreq      = 89,
    Emsgsize          = 90,
    Esocktnosupport   = 94,
    Enotconn          = 107,
    Etimedout         = 110,
}

impl Errno {
    /// Raw Linux errno number.
    /// # C: O(1)
    pub const fn as_i32(self) -> i32 { self as i32 }
}

/// Crate-wide result. The dispatch path encodes `Err(e)` as
/// `-(e.as_i32() as i64)` per `15§1.3`.
pub type KResult<T> = core::result::Result<T, Errno>;
