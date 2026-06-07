// 024 sched_yield — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sched_yield()` — slot 24. tick_yield + 0.
/// # C: O(log N)
pub fn sys_sched_yield(_args: &SyscallArgs) -> i64 {
    if sched::live::global().is_some() {
        // SAFETY: process ctx; runqueue installed; preempt-off through the syscall handler; tick_yield saves into current.arch_ctx + Context::switch's away.
        unsafe { sched::live::tick_yield(); }
    }
    0
}
