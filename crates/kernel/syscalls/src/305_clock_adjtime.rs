// 305 clock_adjtime — one syscall, one file (docs/53 §0).
// Shim only: `timex_policy::clock_adjtime` owns the clock admission and the
// conditional copy-back that distinguish it from slot 159.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::timex_ops::KernelTimexOps;

/// `sys_clock_adjtime(which_clock, utx)` — slot 305. Only CLOCK_REALTIME has a
/// `k_clock::clock_adj`; other table entries are EOPNOTSUPP and ids outside the
/// table are EINVAL.
/// # C: O(1)
pub fn sys_clock_adjtime(args: &SyscallArgs) -> i64 {
    match crate::timex_policy::clock_adjtime(&mut KernelTimexOps, args.a0, args.a1) {
        Ok(state) => state as i64,
        Err(errno) => -(errno.as_i32() as i64),
    }
}
