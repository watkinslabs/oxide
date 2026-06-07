// 228 clock_gettime — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::userbuf::validate_user_buf;
use crate::time_common::{NS_PER_SEC, ns_for_clock};

/// `sys_clock_gettime(clk_id, tp)` — slot 228. Writes
/// `{tv_sec, tv_nsec}` for the given clock per `28§4`.
/// # C: O(1)
pub fn kernel_clock_gettime(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let tp = args.a1;
    if let Err(rv) = validate_user_buf(tp, 16, 8) { return rv; }
    let ns = ns_for_clock(clk_id);
    let tv_sec  = ns / NS_PER_SEC;
    let tv_nsec = ns % NS_PER_SEC;
    // SAFETY: tp validated 16-byte range below USER_VA_END + 8-byte aligned; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile(tp as *mut u64,         tv_sec);
        core::ptr::write_volatile((tp + 8) as *mut u64,   tv_nsec);
    }
    0
}
