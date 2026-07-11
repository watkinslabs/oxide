// 199 fremovexattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_fremovexattr(fd, name)` — slot 199. # C: O(N_xattrs)
pub fn sys_fremovexattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_fremovexattr(args) }
