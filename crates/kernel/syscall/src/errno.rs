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
    Enotblk = 15,
    Ebusy   = 16,
    Eexist  = 17,
    Enodev  = 19,
    Exdev   = 18,
    Enotdir = 20,
    Eisdir  = 21,
    Einval  = 22,
    Enfile  = 23,
    Emfile  = 24,
    Enotty  = 25,
    Etxtbsy = 26,
    Efbig   = 27,
    Espipe  = 29,
    Emlink  = 31,
    Erofs   = 30,
    Enospc  = 28,
    Epipe   = 32,
    Erange  = 34,
    Enametoolong = 36,
    Enosys  = 38,
    Enotempty = 39,
    Eloop   = 40,
    Eidrm   = 43,
    Enomsg  = 42,
    Ebade   = 52,
    Enodata = 61,
    Enopkg  = 65,
    Enonet  = 64,
    Eproto  = 71,
    Ehostdown = 112,
    Eoverflow         = 75,
    Eusers            = 87,
    Enoprotoopt       = 92,
    Eopnotsupp        = 95,
    Epfnsupport       = 96,
    Eafnosupport      = 97,
    Eaddrinuse        = 98,
    Eaddrnotavail     = 99,
    Enetdown          = 100,
    Enetunreach       = 101,
    Econnaborted      = 103,
    Enobufs           = 105,
    Eisconn           = 106,
    Enotsock          = 88,
    Edestaddrreq      = 89,
    Emsgsize          = 90,
    Eprototype        = 91,
    Eprotonosupport   = 93,
    Esocktnosupport   = 94,
    Enotconn          = 107,
    Etimedout         = 110,
    Econnrefused      = 111,
    Ehostunreach      = 113,
    Ealready          = 114,
    Einprogress       = 115,
    Econnreset        = 104,
    Estale            = 116,
    Euclean           = 117,
    Edquot            = 122,
    Ecanceled         = 125,
    Eftype            = 134,
}

impl Errno {
    /// Raw Linux errno number.
    /// # C: O(1)
    pub const fn as_i32(self) -> i32 { self as i32 }
}

/// Crate-wide result. The dispatch path encodes `Err(e)` as
/// `-(e.as_i32() as i64)` per `15§1.3`.
pub type KResult<T> = core::result::Result<T, Errno>;
