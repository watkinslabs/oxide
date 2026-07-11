// 227 clock_settime — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;
use crate::time_common::{NS_PER_SEC, CLOCK_REALTIME, REALTIME_OFFSET_NS, monotonic_ns};

/// `sys_clock_settime(clk_id, tp)` — slot 227. CLOCK_REALTIME
/// updates `REALTIME_OFFSET_NS` so subsequent reads return the
/// caller-supplied wall-clock time. Other clocks: accept + forget.
/// # C: O(1)
pub fn kernel_clock_settime(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let tp = args.a1;
    if !matches!(clk_id, CLOCK_REALTIME) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Err(rv) = validate_user_buf(tp, 16, 1) { return rv; }
    // SAFETY: tp validated as readable 16-byte timespec storage.
    let (sec, nsec) = unsafe {
        let s = core::ptr::read_unaligned(tp as *const i64);
        let n = core::ptr::read_unaligned((tp + 8) as *const i64);
        (s, n)
    };
    if sec < 0 || nsec < 0 || nsec >= NS_PER_SEC as i64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let target = (sec as u64).saturating_mul(NS_PER_SEC).saturating_add(nsec as u64);
    REALTIME_OFFSET_NS.store(sched::clock::settimeofday_offset(monotonic_ns(), target), Ordering::Release);
    0
}
