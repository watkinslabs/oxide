// 189 lsetxattr — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_lsetxattr(path, name, value, size, flags)` — slot 189. # C: O(N_path + N_xattrs)
pub fn sys_lsetxattr(args: &SyscallArgs) -> i64 { crate::xattr_common::sys_setxattr_path(args, false) }
