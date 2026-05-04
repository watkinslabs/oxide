// P3-30 time-shaped syscalls split out of `syscall_glue.rs`
// to keep that file under the 1000-line cap per `08§7`.
// Houses clock_gettime/clock_getres/clock_settime/gettimeofday/time.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use hal::TimerOps;

use crate::syscall_glue::validate_user_buf;

const NS_PER_SEC: u64 = 1_000_000_000;

#[inline]
fn monotonic_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// `sys_clock_gettime(clk_id, tp)` — slot 228. Writes
/// `{tv_sec, tv_nsec}` from the per-arch monotonic counter.
/// v1 ignores `clk_id` (CLOCK_REALTIME / CLOCK_MONOTONIC alike).
/// # C: O(1)
pub fn kernel_clock_gettime(args: &SyscallArgs) -> i64 {
    let _clk_id = args.a0;
    let tp = args.a1;
    if let Err(rv) = validate_user_buf(tp, 16, 8) { return rv; }
    let ns = monotonic_ns();
    let tv_sec  = ns / NS_PER_SEC;
    let tv_nsec = ns % NS_PER_SEC;
    // SAFETY: tp validated 16-byte range below USER_VA_END + 8-byte aligned; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile(tp as *mut u64,         tv_sec);
        core::ptr::write_volatile((tp + 8) as *mut u64,   tv_nsec);
    }
    0
}

/// `sys_clock_getres(clk_id, res)` — slot 229. v1 reports 1 ns
/// resolution (the precision of the monotonic counter).
/// # C: O(1)
pub fn kernel_clock_getres(args: &SyscallArgs) -> i64 {
    let _clk_id = args.a0;
    let tp = args.a1;
    if tp == 0 { return 0; }
    if let Err(rv) = validate_user_buf(tp, 16, 8) { return rv; }
    // SAFETY: tp validated 16-byte range below USER_VA_END + 8-byte aligned; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile(tp as *mut u64, 0);
        core::ptr::write_volatile((tp + 8) as *mut u64, 1);
    }
    0
}

/// `sys_clock_settime(clk_id, tp)` — slot 227. v1 has no RTC;
/// accept and forget.
/// # C: O(1)
pub fn kernel_clock_settime(_args: &SyscallArgs) -> i64 { 0 }

/// `sys_gettimeofday(tv, tz)` — slot 96. Writes
/// `{tv_sec, tv_usec}` from the monotonic counter (no RTC yet).
/// # C: O(1)
pub fn kernel_gettimeofday(args: &SyscallArgs) -> i64 {
    let tv = args.a0;
    if tv == 0 { return 0; }
    if let Err(rv) = validate_user_buf(tv, 16, 8) { return rv; }
    let ns = monotonic_ns();
    let sec  = ns / NS_PER_SEC;
    let usec = (ns % NS_PER_SEC) / 1000;
    // SAFETY: tv validated 16-byte range below USER_VA_END + 8-byte aligned; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile(tv as *mut u64, sec);
        core::ptr::write_volatile((tv + 8) as *mut u64, usec);
    }
    0
}

/// `sys_time(tloc)` — slot 201. Returns seconds since "epoch"
/// (monotonic counter in v1); writes *tloc if non-NULL.
/// # C: O(1)
pub fn kernel_time(args: &SyscallArgs) -> i64 {
    let sec = (monotonic_ns() / NS_PER_SEC) as i64;
    let tloc = args.a0;
    if tloc != 0 && tloc < hal::USER_VA_END {
        // SAFETY: tloc validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe { core::ptr::write_volatile(tloc as *mut i64, sec); }
    }
    sec
}
