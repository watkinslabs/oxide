// 096 gettimeofday — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::userbuf::validate_user_buf_writable;
use crate::time_common::{NS_PER_SEC, TIMEVAL_SIZE, TIMEZONE_SIZE, TZ_DSTTIME, TZ_MINUTESWEST, realtime_ns};
use crate::user_mem as um;

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
        if um::put_u64(tv, sec).is_err() || um::put_u64(tv + 8, usec).is_err() { return um::EFAULT; }
    }
    if tz != 0 {
        if let Err(rv) = validate_user_buf_writable(tz, TIMEZONE_SIZE, 1) { return rv; }
        let minutes = TZ_MINUTESWEST.load(Ordering::Acquire);
        let dst = TZ_DSTTIME.load(Ordering::Acquire);
        if um::put_i32(tz, minutes).is_err() || um::put_i32(tz + 4, dst).is_err() { return um::EFAULT; }
    }
    0
}
