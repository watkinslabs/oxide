// 471 rseq_slice_yield — one syscall, one file (docs/53 §0).
// Yields the remaining time slice (rseq slice extension); same effect as
// sched_yield on a cooperative+timer scheduler.
use syscall::SyscallArgs;
/// `sys_rseq_slice_yield()` — slot 471.
/// # C: O(1)
pub fn sys_rseq_slice_yield(args: &SyscallArgs) -> i64 {
    crate::proc::sys_sched_yield(args)
}
