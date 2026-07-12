// 188 setxattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_setxattr(path, name, value, size, flags)` — slot 188. # C: O(N_path + N_xattrs)
pub fn sys_setxattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_setxattr_path(args, true) }
