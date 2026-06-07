// 026 msync — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_msync(addr, len, flags)` — slot 26. # C: O(1)
pub fn sys_msync(_args: &SyscallArgs) -> i64 { 0 }
