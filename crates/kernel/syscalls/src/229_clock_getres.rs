// 229 clock_getres — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::userbuf::validate_user_buf;

/// `sys_clock_getres(clk_id, res)` — slot 229. v1 reports 1 ns
/// resolution (the precision of the monotonic counter).
/// # C: O(1)
pub fn kernel_clock_getres(args: &SyscallArgs) -> i64 {
    let _clk_id = args.a0;
    let tp = args.a1;
    if tp == 0 { return 0; }
    if let Err(rv) = validate_user_buf(tp, 16, 8) { return rv; }
    // SAFETY: tp validated 16-byte range below USER_VA_END + 8-byte aligned; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile(tp as *mut u64, 0);
        core::ptr::write_volatile((tp + 8) as *mut u64, 1);
    }
    0
}
