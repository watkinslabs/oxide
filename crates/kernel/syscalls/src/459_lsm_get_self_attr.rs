// 459 lsm_get_self_attr — one syscall, one file (docs/53 §0).
//
// No LSM is registered, so no module supplies the getselfattr hook and Linux's
// `count == 0` path returns `LSM_RET_DEFAULT(getselfattr)` = EOPNOTSUPP. That
// is the terminal answer for a WELL-FORMED call only: `security_getselfattr`
// validates its arguments first, so a malformed call must still get EINVAL or
// EFAULT. Returning EOPNOTSUPP unconditionally hid every caller bug behind a
// capability report.

use syscall::{errno::Errno, SyscallArgs};
use crate::lsm::{getselfattr_precheck, NO_LSM_RESULT};

/// `sys_lsm_get_self_attr(attr, ctx, size, flags)` — slot 459.
/// # C: O(1)
pub fn sys_lsm_get_self_attr(args: &SyscallArgs) -> i64 {
    let (attr, uctx, size_ptr, flags) = (args.a0 as u32, args.a1, args.a2, args.a3 as u32);
    if let Err(e) = getselfattr_precheck(attr, uctx, size_ptr, flags) {
        return -(e.as_i32() as i64);
    }
    // Linux reads the caller's `size` before consulting any LSM, so a bad
    // pointer is EFAULT rather than EOPNOTSUPP.
    let mut left = [0u8; 4];
    if uaccess::copy_from_user(&mut left, size_ptr).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    // With LSM_FLAG_SINGLE the caller's lsm_ctx is read next, and an
    // unspecified module id is EINVAL.
    if flags == crate::lsm::LSM_FLAG_SINGLE {
        let mut id = [0u8; 8];
        if uaccess::copy_from_user(&mut id, uctx).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        if u64::from_ne_bytes(id) == crate::lsm::LSM_ID_UNDEF {
            return -(Errno::Einval.as_i32() as i64);
        }
    }
    -(NO_LSM_RESULT.as_i32() as i64)
}
