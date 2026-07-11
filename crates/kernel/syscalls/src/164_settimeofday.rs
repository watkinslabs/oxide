// 164 settimeofday — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;
use crate::time_common::{NS_PER_SEC, REALTIME_OFFSET_NS, monotonic_ns};

/// `sys_settimeofday(tv, tz)` — slot 164. Writes REALTIME_OFFSET_NS
/// from `tv` so subsequent gettimeofday/time return wall-clock.
/// # C: O(1)
pub fn kernel_settimeofday(args: &SyscallArgs) -> i64 {
    let tv = args.a0;
    if tv == 0 { return 0; }
    if let Err(rv) = validate_user_buf(tv, 16, 8) { return rv; }
    // SAFETY: tv validated as readable 16-byte timeval storage.
    let (sec, usec) = unsafe {
        let s = core::ptr::read_volatile(tv as *const i64);
        let u = core::ptr::read_volatile((tv + 8) as *const i64);
        (s, u)
    };
    if sec < 0 || usec < 0 || usec >= 1_000_000 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let target = (sec as u64).saturating_mul(NS_PER_SEC).saturating_add((usec as u64).saturating_mul(1000));
    REALTIME_OFFSET_NS.store(sched::clock::settimeofday_offset(monotonic_ns(), target), Ordering::Release);
    0
}
