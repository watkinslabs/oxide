// 164 settimeofday — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;
use crate::time_common::{NSEC_PER_USEC, NS_PER_SEC, REALTIME_OFFSET_NS, TIMEVAL_SIZE, TIMEZONE_SIZE, TZ_DSTTIME, TZ_MINUTESWEST, TZ_MINUTESWEST_LIMIT, USEC_PER_SEC, monotonic_ns};

/// `sys_settimeofday(tv, tz)` — slot 164. Writes REALTIME_OFFSET_NS
/// from `tv` so subsequent gettimeofday/time return wall-clock.
/// # C: O(1)
pub fn kernel_settimeofday(args: &SyscallArgs) -> i64 {
    let tv = args.a0;
    let tz = args.a1;
    let tv_pair = if tv != 0 {
        if let Err(rv) = validate_user_buf(tv, TIMEVAL_SIZE, 1) { return rv; }
        // SAFETY: tv validated readable for one timeval; unaligned loads match Linux copy_from_user layout.
        let (sec, usec) = unsafe {
            let s = core::ptr::read_unaligned(tv as *const i64);
            let u = core::ptr::read_unaligned((tv + 8) as *const i64);
            (s, u)
        };
        if sec < 0 || usec < 0 || usec >= USEC_PER_SEC as i64 {
            return -(Errno::Einval.as_i32() as i64);
        }
        Some((sec as u64, usec as u64))
    } else {
        None
    };
    let tz_pair = if tz != 0 {
        if let Err(rv) = validate_user_buf(tz, TIMEZONE_SIZE, 1) { return rv; }
        // SAFETY: tz validated readable for one timezone; unaligned loads match Linux copy_from_user layout.
        let (minutes, dst) = unsafe {
            let m = core::ptr::read_unaligned(tz as *const i32);
            let d = core::ptr::read_unaligned((tz + 4) as *const i32);
            (m, d)
        };
        if !(-TZ_MINUTESWEST_LIMIT..=TZ_MINUTESWEST_LIMIT).contains(&minutes) {
            return -(Errno::Einval.as_i32() as i64);
        }
        Some((minutes, dst))
    } else {
        None
    };
    if let Some((minutes, dst)) = tz_pair {
        TZ_MINUTESWEST.store(minutes, Ordering::Release);
        TZ_DSTTIME.store(dst, Ordering::Release);
    }
    if let Some((sec, usec)) = tv_pair {
        let target = sec.saturating_mul(NS_PER_SEC).saturating_add(usec.saturating_mul(NSEC_PER_USEC));
        REALTIME_OFFSET_NS.store(sched::clock::settimeofday_offset(monotonic_ns(), target), Ordering::Release);
        sched::clock::note_realtime_change();
    }
    0
}
