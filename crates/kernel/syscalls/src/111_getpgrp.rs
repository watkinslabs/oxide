// 111 getpgrp — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getpgrp` — slot 111. Returns the current task's pgid.
/// # C: O(1)
pub fn sys_getpgrp(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|c| c.pgid.load(Ordering::Acquire) as i64).unwrap_or(1)
}
