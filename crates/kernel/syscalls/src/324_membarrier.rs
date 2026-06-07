// 324 membarrier — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_membarrier(cmd, flags, cpu_id)` — slot 324. v1 single-
/// CPU UP: every memory op is already globally ordered, so any
/// MEMBARRIER_CMD_* request succeeds vacuously.
/// # C: O(1)
pub fn sys_membarrier(_args: &SyscallArgs) -> i64 { 0 }
