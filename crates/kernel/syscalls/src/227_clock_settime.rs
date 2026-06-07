// 227 clock_settime — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;

use crate::time_common::{NS_PER_SEC, CLOCK_REALTIME, REALTIME_OFFSET_NS, monotonic_ns};

/// `sys_clock_settime(clk_id, tp)` — slot 227. CLOCK_REALTIME
/// updates `REALTIME_OFFSET_NS` so subsequent reads return the
/// caller-supplied wall-clock time. Other clocks: accept + forget.
/// # C: O(1)
pub fn kernel_clock_settime(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let tp = args.a1;
    if tp == 0 || tp >= hal::USER_VA_END { return 0; }
    // SAFETY: tp validated 16-byte range; CPL=0 reads through caller's AS.
    let (sec, nsec) = unsafe {
        let s = core::ptr::read_volatile(tp as *const u64);
        let n = core::ptr::read_volatile((tp + 8) as *const u64);
        (s, n)
    };
    if matches!(clk_id, CLOCK_REALTIME) {
        let target = sec.saturating_mul(NS_PER_SEC).saturating_add(nsec);
        REALTIME_OFFSET_NS.store(sched::clock::settimeofday_offset(monotonic_ns(), target), Ordering::Release);
    }
    0
}
