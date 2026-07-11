// 195 llistxattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_llistxattr(path, list, size)` — slot 195. # C: O(N_path + N_xattrs)
pub fn sys_llistxattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_listxattr_path(args, false) }
