// 228 clock_gettime — one syscall, one file (docs/53 §0).
// Shim only: `clock_policy::clock_gettime` owns the decision order.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::clock_ops::KernelClockOps;

/// `sys_clock_gettime(clk_id, tp)` — slot 228.
/// # C: O(1), O(N_tasks) for a CPU clock
pub fn kernel_clock_gettime(args: &SyscallArgs) -> i64 {
    match crate::clock_policy::clock_gettime(&mut KernelClockOps, args.a0, args.a1) {
        Ok(()) => 0,
        Err(errno) => -(errno.as_i32() as i64),
    }
}
