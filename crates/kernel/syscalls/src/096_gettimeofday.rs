// 096 gettimeofday — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::userbuf::validate_user_buf_writable;
use crate::time_common::{NS_PER_SEC, TIMEVAL_SIZE, TIMEZONE_SIZE, TZ_DSTTIME, TZ_MINUTESWEST, realtime_ns};

/// `sys_gettimeofday(tv, tz)` — slot 96. Writes
/// `{tv_sec, tv_usec}` from the wall-clock (monotonic + offset).
/// # C: O(1)
pub fn kernel_gettimeofday(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let tv = args.a0;
    let tz = args.a1;
    if tv != 0 {
        if let Err(rv) = validate_user_buf_writable(tv, TIMEVAL_SIZE, 1) { return rv; }
        let ns = realtime_ns();
        let sec  = ns / NS_PER_SEC;
        let usec = (ns % NS_PER_SEC) / 1000;
        // SAFETY: tv validated writable for the full timeval; unaligned stores match Linux copy_to_user layout.
        unsafe {
            core::ptr::write_unaligned(tv as *mut u64, sec);
            core::ptr::write_unaligned((tv + 8) as *mut u64, usec);
        }
    }
    if tz != 0 {
        if let Err(rv) = validate_user_buf_writable(tz, TIMEZONE_SIZE, 1) { return rv; }
        let minutes = TZ_MINUTESWEST.load(Ordering::Acquire);
        let dst = TZ_DSTTIME.load(Ordering::Acquire);
        // SAFETY: tz validated writable for the full timezone; unaligned stores match Linux copy_to_user layout.
        unsafe {
            core::ptr::write_unaligned(tz as *mut i32, minutes);
            core::ptr::write_unaligned((tz + 4) as *mut i32, dst);
        }
    }
    0
}
