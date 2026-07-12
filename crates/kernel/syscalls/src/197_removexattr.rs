// 197 removexattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_removexattr(path, name)` — slot 197. # C: O(N_path + N_xattrs)
pub fn sys_removexattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_removexattr_path(args, true) }
