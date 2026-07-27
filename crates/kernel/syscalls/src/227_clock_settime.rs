// 227 clock_settime — one syscall, one file (docs/53 §0).
// Shim only: `clock_policy::clock_settime` owns the decision order, which is
// observable — EINVAL(clock), EFAULT(pointer), EINVAL(value), EPERM(CAP_SYS_TIME).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::clock_ops::KernelClockOps;

/// `sys_clock_settime(clk_id, tp)` — slot 227. CLOCK_REALTIME updates the
/// canonical wall clock and reprojects absolute realtime timer deadlines.
/// # C: O(1)
pub fn kernel_clock_settime(args: &SyscallArgs) -> i64 {
    match crate::clock_policy::clock_settime(&mut KernelClockOps, args.a0, args.a1) {
        Ok(()) => 0,
        Err(errno) => -(errno.as_i32() as i64),
    }
}
