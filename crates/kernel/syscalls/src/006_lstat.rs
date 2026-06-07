// 006 lstat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_lstat(path, statbuf)` — slot 6. Does NOT follow a final symlink.
/// Shares `stat_impl` with sys_stat (`004_stat.rs`).
/// # C: O(path components × dir-lookup)
pub fn sys_lstat(args: &SyscallArgs) -> i64 { crate::s004_stat::stat_impl(args, false) }
