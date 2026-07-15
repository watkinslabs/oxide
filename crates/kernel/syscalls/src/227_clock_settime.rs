// 227 clock_settime — one syscall, one file (docs/53 §0). Moved verbatim from time.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;
use crate::time_common::{NS_PER_SEC, CLOCK_REALTIME};

/// `sys_clock_settime(clk_id, tp)` — slot 227. CLOCK_REALTIME updates the
/// canonical wall clock and reprojects absolute realtime timer deadlines.
/// # C: O(1)
pub fn kernel_clock_settime(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let tp = args.a1;
    if !matches!(clk_id, CLOCK_REALTIME) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(cur) = sched::live::current() else { return -(Errno::Esrch.as_i32() as i64) };
    if !cur.has_cap(sched::cap::SYS_TIME) { return -(Errno::Eperm.as_i32() as i64); }
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
    timekeeper::set_realtime(target);
    sched::timers::clock_was_set();
    0
}
