//! Translating between the layer's error type and this crate's.
//!
//! Both spell the same Linux numbers, but they are different types, and the
//! translation is where a specific failure quietly becomes a generic one. That
//! matters here more than usual: a caller distinguishes `ENODATA` (nothing
//! recorded) from `ESTALE` (something else recorded) to decide whether to
//! write a record or refuse a merge, and collapsing either into `EIO` turns a
//! recoverable state into a broken mount.

use syscall::errno::Errno;
use vfs::VfsError;

/// A layer failure as an errno. # C: O(1)
pub fn to_errno(e: VfsError) -> Errno {
    match e {
        VfsError::Eperm => Errno::Eperm,
        VfsError::Enoent => Errno::Enoent,
        VfsError::Eio => Errno::Eio,
        VfsError::Enxio => Errno::Enxio,
        VfsError::Eagain => Errno::Eagain,
        VfsError::Enomem => Errno::Enomem,
        VfsError::Eacces => Errno::Eacces,
        VfsError::Ebusy => Errno::Ebusy,
        VfsError::Eexist => Errno::Eexist,
        VfsError::Exdev => Errno::Exdev,
        VfsError::Enodev => Errno::Enodev,
        VfsError::Enotdir => Errno::Enotdir,
        VfsError::Eisdir => Errno::Eisdir,
        VfsError::Einval => Errno::Einval,
        VfsError::Efbig => Errno::Efbig,
        VfsError::Enospc => Errno::Enospc,
        VfsError::Erofs => Errno::Erofs,
        VfsError::Emlink => Errno::Emlink,
        VfsError::Enametoolong => Errno::Enametoolong,
        VfsError::Enotempty => Errno::Enotempty,
        VfsError::Eloop => Errno::Eloop,
        VfsError::Enodata => Errno::Enodata,
        VfsError::Eopnotsupp => Errno::Eopnotsupp,
        VfsError::Estale => Errno::Estale,
        VfsError::Edquot => Errno::Edquot,
        VfsError::Eoverflow => Errno::Eoverflow,
        VfsError::Eintr => Errno::Eintr,
        VfsError::Etxtbsy => Errno::Etxtbsy,
        _ => Errno::Eio,
    }
}

/// An errno as a layer failure. # C: O(1)
pub fn to_vfs(e: Errno) -> VfsError {
    match e {
        Errno::Eperm => VfsError::Eperm,
        Errno::Enoent => VfsError::Enoent,
        Errno::Eio => VfsError::Eio,
        Errno::Enxio => VfsError::Enxio,
        Errno::Eagain => VfsError::Eagain,
        Errno::Enomem => VfsError::Enomem,
        Errno::Eacces => VfsError::Eacces,
        Errno::Ebusy => VfsError::Ebusy,
        Errno::Eexist => VfsError::Eexist,
        Errno::Exdev => VfsError::Exdev,
        Errno::Enodev => VfsError::Enodev,
        Errno::Enotdir => VfsError::Enotdir,
        Errno::Eisdir => VfsError::Eisdir,
        Errno::Einval => VfsError::Einval,
        Errno::Efbig => VfsError::Efbig,
        Errno::Enospc => VfsError::Enospc,
        Errno::Erofs => VfsError::Erofs,
        Errno::Emlink => VfsError::Emlink,
        Errno::Enametoolong => VfsError::Enametoolong,
        Errno::Enotempty => VfsError::Enotempty,
        Errno::Eloop => VfsError::Eloop,
        Errno::Enodata => VfsError::Enodata,
        Errno::Eopnotsupp => VfsError::Eopnotsupp,
        Errno::Estale => VfsError::Estale,
        Errno::Edquot => VfsError::Edquot,
        Errno::Eoverflow => VfsError::Eoverflow,
        Errno::Eintr => VfsError::Eintr,
        Errno::Etxtbsy => VfsError::Etxtbsy,
        _ => VfsError::Eio,
    }
}

#[cfg(test)]
#[path = "err/tests.rs"]
mod tests;
