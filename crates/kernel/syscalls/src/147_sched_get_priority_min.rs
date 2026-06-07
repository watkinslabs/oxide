// 147 sched_get_priority_min — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sched_get_priority_min(policy)` — slot 147.  1 for
/// SCHED_FIFO/RR, 0 otherwise.
/// # C: O(1)
pub fn sys_sched_get_priority_min(args: &SyscallArgs) -> i64 {
    let policy = args.a0 as i32;
    match policy { 1 | 2 => 1, _ => 0 }
}
