// 198 lremovexattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_lremovexattr(path, name)` — slot 198. # C: O(N_path + N_xattrs)
pub fn sys_lremovexattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_removexattr_path(args, false) }
