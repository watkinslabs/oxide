// 295 preadv — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_preadv(fd, iov, iovcnt, off)` — slot 295. Same offset
/// caveat as pwritev.
/// # C: O(1)
pub fn sys_preadv(args: &SyscallArgs) -> i64 { crate::s019_readv::sys_readv(args) }
