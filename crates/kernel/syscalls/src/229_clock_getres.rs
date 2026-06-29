// 229 clock_getres — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;
use crate::time_common::{
    clock_id_known, CLOCK_MONOTONIC_COARSE, CLOCK_REALTIME_COARSE,
};

/// `sys_clock_getres(clk_id, res)` — slot 229.
/// # C: O(1)
pub fn kernel_clock_getres(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let tp = args.a1;
    if !clock_id_known(clk_id) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if tp == 0 { return 0; }
    if let Err(rv) = validate_user_buf(tp, 16, 8) { return rv; }
    let nsec = match clk_id {
        CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE => 1_000_000,
        _ => 1,
    };
    // SAFETY: tp validated 16-byte range below USER_VA_END + 8-byte aligned; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile(tp as *mut u64, 0);
        core::ptr::write_volatile((tp + 8) as *mut u64, nsec);
    }
    0
}
