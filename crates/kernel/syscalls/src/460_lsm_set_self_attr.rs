// 460 lsm_set_self_attr — one syscall, one file (docs/53 §0).
//
// No LSM is loaded → no module accepts a self-attribute write. Linux returns
// EOPNOTSUPP when no LSM supports the attribute — match it.

use syscall::{errno::Errno, SyscallArgs};

/// `sys_lsm_set_self_attr(attr, ctx, size, flags)` — slot 460.
/// # C: O(1)
pub fn sys_lsm_set_self_attr(_args: &SyscallArgs) -> i64 {
    -(Errno::Eopnotsupp.as_i32() as i64)
}
