// 196 flistxattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_flistxattr(fd, list, size)` — slot 196. # C: O(N_xattrs)
pub fn sys_flistxattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_flistxattr(args) }
