// 192 lgetxattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_lgetxattr(path, name, value, size)` — slot 192. # C: O(N_path + N_xattrs)
pub fn sys_lgetxattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_getxattr_path(args, false) }
