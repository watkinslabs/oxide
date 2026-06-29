// 296 pwritev — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_pwritev(fd, iov, iovcnt, off)` — slot 296. v1 ignores
/// the offset (acts like writev) for non-seekable backends; for
/// regular files this yields posix-correct results when the file
/// position equals `off` (the common stdio case post-fseek).
/// # C: O(iovcnt × iov[i].len)
pub fn sys_pwritev(args: &SyscallArgs) -> i64 { crate::s020_writev::sys_writev(args) }

/// `sys_pwritev2(fd, iov, iovcnt, pos_l, pos_h, flags)`. Validates the RWF_*
/// `flags` word (Linux `kiocb_set_rw_flags`: an unsupported bit → EOPNOTSUPP)
/// the plain `pwritev` handler silently dropped, then writes (D54). RWF_APPEND
/// is accepted but acts only when the fd carries O_APPEND (writev forces EOF);
/// per-call RWF_APPEND offset handling rides the offset-plumbing residual.
/// # C: O(iovcnt × iov[i].len)
pub fn sys_pwritev2(args: &SyscallArgs) -> i64 {
    if args.a5 & !crate::s295_preadv::RWF_SUPPORTED != 0 {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    sys_pwritev(args)
}
