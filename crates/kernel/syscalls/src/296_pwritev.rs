// 296 pwritev — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_pwritev(fd, iov, iovcnt, off)` — slot 296. v1 ignores
/// the offset (acts like writev) for non-seekable backends; for
/// regular files this yields posix-correct results when the file
/// position equals `off` (the common stdio case post-fseek).
/// # C: O(iovcnt × iov[i].len)
pub fn sys_pwritev(args: &SyscallArgs) -> i64 { crate::s020_writev::sys_writev(args) }
