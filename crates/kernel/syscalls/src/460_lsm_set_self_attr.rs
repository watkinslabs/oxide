// 460 lsm_set_self_attr — one syscall, one file (docs/53 §0).
//
// No LSM is registered, so no module claims the setselfattr hook and Linux
// falls through to `LSM_RET_DEFAULT(setselfattr)` = EOPNOTSUPP. As with slot
// 459 that is the answer for a WELL-FORMED call only: `security_setselfattr`
// validates flags/size and copies the caller's buffer first, so malformed
// calls must still get EINVAL, E2BIG, or EFAULT.

use syscall::{errno::Errno, SyscallArgs};
use crate::lsm::{setselfattr_precheck, LSM_CTX_SIZE, NO_LSM_RESULT};

/// `sys_lsm_set_self_attr(attr, ctx, size, flags)` — slot 460.
/// # C: O(1)
pub fn sys_lsm_set_self_attr(args: &SyscallArgs) -> i64 {
    let (attr, uctx, size, flags) = (args.a0 as u32, args.a1, args.a2 as u32, args.a3 as u32);
    if let Err(e) = setselfattr_precheck(attr, size, flags) {
        return -(e.as_i32() as i64);
    }
    // Linux `memdup_user`s the whole ctx before looking for a module, so a bad
    // buffer is EFAULT, not EOPNOTSUPP. Reading the fixed header is enough to
    // fault-check the pointer and to validate the declared lengths below.
    let mut hdr = [0u8; LSM_CTX_SIZE as usize];
    if uaccess::copy_from_user(&mut hdr, uctx).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let len     = u64::from_ne_bytes(hdr[16..24].try_into().unwrap_or([0; 8]));
    let ctx_len = u64::from_ne_bytes(hdr[24..32].try_into().unwrap_or([0; 8]));
    // `size < lctx->len`, or `sizeof(*lctx) + ctx_len` overflowing, or
    // `lctx->len < required_len` -> EINVAL (Linux checks all three together).
    let required = (LSM_CTX_SIZE as u64).checked_add(ctx_len);
    match required {
        Some(req) if (size as u64) >= len && len >= req => {}
        _ => return -(Errno::Einval.as_i32() as i64),
    }
    -(NO_LSM_RESULT.as_i32() as i64)
}
