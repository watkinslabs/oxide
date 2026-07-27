// sys_clock_nanosleep per docs/15§5. Extracted from proc.rs to
// keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};
use crate::time_common::{NS_PER_SEC, clock_id_known, clock_nanosleep_supported,
    current_sleep_target_to_host, ns_for_clock};

const TIMER_ABSTIME: u64 = 0x1;

/// `sys_clock_nanosleep(clk_id, flags, req, rem)` — slot 230.
/// TIMER_ABSTIME treats req as an absolute timestamp; otherwise
/// req is the relative sleep duration.
/// # C: O(1) + sleep cost
pub fn sys_clock_nanosleep(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let flags = args.a1;
    let req   = args.a2;
    let rem   = args.a3;
    if !clock_id_known(clk_id) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if !clock_nanosleep_supported(clk_id) {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    if crate::time_common::clock_is_alarm(clk_id) {
        let Some(cur) = sched::live::current() else {
            return -(Errno::Esrch.as_i32() as i64);
        };
        if !cur.has_cap(sched::cap::WAKE_ALARM) {
            return -(Errno::Eperm.as_i32() as i64);
        }
    }
    if let Err(rv) = validate_user_buf(req, 16, 1) { return rv; }
    // SAFETY: req validated as readable 16-byte timespec storage.
    let (secs, nsec) = unsafe {
        let s = core::ptr::read_unaligned(req as *const i64);
        let n = core::ptr::read_unaligned((req + 8) as *const i64);
        (s, n)
    };
    // `ktime_set`-clamped decode: TIMER_ABSTIME with a huge-but-valid tv_sec
    // clamps to KTIME_MAX_NS instead of an unbounded absolute deadline.
    let target_ns = match ::syscall::time::timespec_to_ns(secs, nsec) {
        Ok(ns) => ns,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let is_abs = (flags & TIMER_ABSTIME) != 0;
    let host_target = match current_sleep_target_to_host(clk_id, is_abs, target_ns) {
        Ok(ns) => ns,
        Err(_) => return -(Errno::Eio.as_i32() as i64),
    };
    let rel_ns = if is_abs {
        let host_now = ns_for_clock(clk_id);
        if host_target <= host_now { return 0; }
        host_target - host_now
    } else {
        host_target
    };
    let start = monotonic();
    let deadline = start.saturating_add(rel_ns);
    let cur = sched::live::current();
    loop {
        if monotonic() >= deadline { break; }
        // Interruptible: an unblocked pending signal aborts with EINTR. A
        // RELATIVE sleep reports the time left in `rem`; TIMER_ABSTIME does not
        // (Linux clock_nanosleep). Mirror of the poll/pselect6 EINTR check.
        if let Some(c) = cur {
            use core::sync::atomic::Ordering;
            let pending = c.sigpending.load(Ordering::Acquire);
            let mask    = c.sigmask.load(Ordering::Acquire);
            if pending & !mask != 0 {
                if !is_abs && rem != 0 {
                    if let Err(rv) = validate_user_buf_writable(rem, 16, 1) { return rv; }
                    let left  = deadline.saturating_sub(monotonic());
                    let rsec  = (left / NS_PER_SEC) as i64;
                    let rnsec = (left % NS_PER_SEC) as i64;
                    // SAFETY: rem validated writable for a 16-byte timespec.
                    unsafe {
                        core::ptr::write_unaligned(rem as *mut i64, rsec);
                        core::ptr::write_unaligned((rem + 8) as *mut i64, rnsec);
                    }
                }
                return -(Errno::Eintr.as_i32() as i64);
            }
        }
        // SAFETY: process ctx; runqueue installed; preempt-off; voluntary tick_yield re-enters scheduler.
        unsafe { sched::live::tick_yield(); }
    }
    0
}

#[inline]
fn monotonic() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}
