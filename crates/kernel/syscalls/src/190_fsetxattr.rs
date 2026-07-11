// 190 fsetxattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_fsetxattr(fd, name, value, size, flags)` — slot 190. # C: O(N_xattrs)
pub fn sys_fsetxattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_fsetxattr(args) }
