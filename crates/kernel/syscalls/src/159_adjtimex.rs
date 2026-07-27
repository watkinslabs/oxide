// 159 adjtimex — one syscall, one file (docs/53 §0).
// Shim only: `timex_policy::adjtimex` owns the copy-in/copy-back order and
// `timekeeper::ntp` owns the discipline loop.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::timex_ops::KernelTimexOps;

/// `sys_adjtimex(txc_p)` — slot 159. Returns the `TIME_*` clock state
/// (0..=5) on success, which glibc passes straight through; a mutating mode
/// needs CAP_SYS_TIME, a `modes == 0` query needs nothing.
/// # C: O(1)
pub fn sys_adjtimex(args: &SyscallArgs) -> i64 {
    match crate::timex_policy::adjtimex(&mut KernelTimexOps, args.a0) {
        Ok(state) => state as i64,
        Err(errno) => -(errno.as_i32() as i64),
    }
}
