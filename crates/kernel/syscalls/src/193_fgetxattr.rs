// 193 fgetxattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_fgetxattr(fd, name, value, size)` — slot 193. # C: O(N_xattrs)
pub fn sys_fgetxattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_fgetxattr(args) }
