// 146 sched_get_priority_max — one syscall, one file (docs/53 §0).
// Linux `sys_sched_get_priority_max`: policy-DEPENDENT, and `-EINVAL` for an
// unknown policy — never a constant. Rule lives in `crate::sched_policy`.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sched_get_priority_max(policy)` — slot 146. 99 for FIFO/RR, 0 for
/// NORMAL/BATCH/IDLE/DEADLINE/EXT, `-EINVAL` otherwise.
/// # C: O(1)
pub fn sys_sched_get_priority_max(args: &SyscallArgs) -> i64 {
    crate::sched_policy::priority_max(args.a0 as i32)
}
