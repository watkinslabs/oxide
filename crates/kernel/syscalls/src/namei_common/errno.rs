//! VFS-to-syscall errno encoding.

use syscall::errno::Errno;

/// Map every VFS failure to the negative Linux errno the ABI returns.
/// # C: O(1)
pub(crate) fn errno_from_vfs(error: vfs::VfsError) -> i64 {
    // `Erestartsys` is NOT an errno — it is Linux's internal restart sentinel
    // (`include/linux/errno.h:12`), produced by every interrupted
    // interruptible VFS wait (`kernel/sched/wait.c:309`). It must reach the
    // dispatch tail intact so `signal_restart_action` can restart the call;
    // mapping it into the errno table here would be exactly the flattening
    // this type exists to prevent. The tail normalizes it to EINTR if no
    // restart happens (`syscall::restart::normalize_user_return`).
    -(match error {
        vfs::VfsError::Erestartsys => return syscall::restart::restart_sys(),
        vfs::VfsError::Eperm => Errno::Eperm, vfs::VfsError::Enoent => Errno::Enoent, vfs::VfsError::Esrch => Errno::Esrch, vfs::VfsError::Eintr => Errno::Eintr,
        vfs::VfsError::Eio => Errno::Eio, vfs::VfsError::Enxio => Errno::Enxio, vfs::VfsError::Ebadf => Errno::Ebadf, vfs::VfsError::Enomem => Errno::Enomem,
        vfs::VfsError::Eacces => Errno::Eacces, vfs::VfsError::Efault => Errno::Efault, vfs::VfsError::Enotblk => Errno::Enotblk, vfs::VfsError::Eexist => Errno::Eexist,
        vfs::VfsError::Exdev => Errno::Exdev, vfs::VfsError::Enodev => Errno::Enodev, vfs::VfsError::Enotdir => Errno::Enotdir, vfs::VfsError::Eisdir => Errno::Eisdir,
        vfs::VfsError::Einval => Errno::Einval, vfs::VfsError::Emfile => Errno::Emfile, vfs::VfsError::Enotty => Errno::Enotty, vfs::VfsError::Etxtbsy => Errno::Etxtbsy,
        vfs::VfsError::Efbig => Errno::Efbig, vfs::VfsError::Espipe => Errno::Espipe, vfs::VfsError::Emlink => Errno::Emlink, vfs::VfsError::Eagain => Errno::Eagain,
        vfs::VfsError::Epipe => Errno::Epipe, vfs::VfsError::Erange => Errno::Erange, vfs::VfsError::Erofs => Errno::Erofs, vfs::VfsError::Ebusy => Errno::Ebusy,
        vfs::VfsError::Enospc => Errno::Enospc, vfs::VfsError::Enotempty => Errno::Enotempty, vfs::VfsError::Enosys => Errno::Enosys, vfs::VfsError::Eloop => Errno::Eloop,
        vfs::VfsError::Ebade => Errno::Ebade, vfs::VfsError::Enodata => Errno::Enodata, vfs::VfsError::Emsgsize => Errno::Emsgsize, vfs::VfsError::Eopnotsupp => Errno::Eopnotsupp, vfs::VfsError::Edestaddrreq => Errno::Edestaddrreq,
        vfs::VfsError::Eaddrnotavail => Errno::Eaddrnotavail, vfs::VfsError::Enetunreach => Errno::Enetunreach, vfs::VfsError::Ehostunreach => Errno::Ehostunreach,
        vfs::VfsError::Enobufs => Errno::Enobufs, vfs::VfsError::Enametoolong => Errno::Enametoolong, vfs::VfsError::Enotconn => Errno::Enotconn,
        vfs::VfsError::Econnaborted => Errno::Econnaborted, vfs::VfsError::Econnreset => Errno::Econnreset, vfs::VfsError::Etimedout => Errno::Etimedout, vfs::VfsError::Econnrefused => Errno::Econnrefused,
        vfs::VfsError::Euclean => Errno::Euclean, vfs::VfsError::Edquot => Errno::Edquot, vfs::VfsError::Ecanceled => Errno::Ecanceled,
        vfs::VfsError::Enonet => Errno::Enonet, vfs::VfsError::Enoprotoopt => Errno::Enoprotoopt, vfs::VfsError::Eproto => Errno::Eproto,
        vfs::VfsError::Ehostdown => Errno::Ehostdown,
    }.as_i32() as i64)
}
