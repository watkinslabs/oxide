// 229 clock_getres — one syscall, one file (docs/53 §0).
// Shim only: `clock_policy::clock_getres` owns the decision order, including
// the NULL-`res` shortcut and the CPU-target validation that precedes it.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::clock_ops::KernelClockOps;

/// `sys_clock_getres(clk_id, res)` — slot 229.
/// # C: O(1), O(N_tasks) for a CPU clock
pub fn kernel_clock_getres(args: &SyscallArgs) -> i64 {
    match crate::clock_policy::clock_getres(&mut KernelClockOps, args.a0, args.a1) {
        Ok(()) => 0,
        Err(errno) => -(errno.as_i32() as i64),
    }
}
