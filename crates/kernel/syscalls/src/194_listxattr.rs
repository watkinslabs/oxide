// 194 listxattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_listxattr(path, list, size)` — slot 194. # C: O(N_path + N_xattrs)
pub fn sys_listxattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_listxattr_path(args, true) }
