// 191 getxattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getxattr(path, name, value, size)` — slot 191. # C: O(N_path + N_xattrs)
pub fn sys_getxattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_getxattr_path(args, true) }
