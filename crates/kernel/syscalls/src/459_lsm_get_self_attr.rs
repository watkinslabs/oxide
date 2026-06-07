// 459 lsm_get_self_attr — one syscall, one file (docs/53 §0).
//
// No LSM is loaded, so no security module exposes a self-attribute. Linux
// returns EOPNOTSUPP when no LSM supports the requested attribute — match it.

use syscall::{errno::Errno, SyscallArgs};

/// `sys_lsm_get_self_attr(attr, ctx, size, flags)` — slot 459.
/// # C: O(1)
pub fn sys_lsm_get_self_attr(_args: &SyscallArgs) -> i64 {
    -(Errno::Eopnotsupp.as_i32() as i64)
}
