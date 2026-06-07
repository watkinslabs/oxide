// 096 gettimeofday — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::userbuf::validate_user_buf;
use crate::time_common::{NS_PER_SEC, realtime_ns};

/// `sys_gettimeofday(tv, tz)` — slot 96. Writes
/// `{tv_sec, tv_usec}` from the wall-clock (monotonic + offset).
/// # C: O(1)
pub fn kernel_gettimeofday(args: &SyscallArgs) -> i64 {
    let tv = args.a0;
    if tv == 0 { return 0; }
    if let Err(rv) = validate_user_buf(tv, 16, 8) { return rv; }
    let ns = realtime_ns();
    let sec  = ns / NS_PER_SEC;
    let usec = (ns % NS_PER_SEC) / 1000;
    // SAFETY: tv validated 16-byte range below USER_VA_END + 8-byte aligned; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile(tv as *mut u64, sec);
        core::ptr::write_volatile((tv + 8) as *mut u64, usec);
    }
    0
}
