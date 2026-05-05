// Time-shaped syscalls. Houses clock_gettime / clock_getres /
// clock_settime / gettimeofday / time / settimeofday.
//
// Real CLOCK_REALTIME tracking: monotonic_ns + REALTIME_OFFSET_NS
// (settable via settimeofday / clock_settime CLOCK_REALTIME). v1
// has no RTC at boot — the offset starts at 0, callers can set it.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::SyscallArgs;
use hal::TimerOps;

use crate::syscall_glue::validate_user_buf;

const NS_PER_SEC: u64 = 1_000_000_000;

const CLOCK_REALTIME:           u64 = 0;
const CLOCK_MONOTONIC:          u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID:  u64 = 3;
const CLOCK_MONOTONIC_RAW:      u64 = 4;
const CLOCK_REALTIME_COARSE:    u64 = 5;
const CLOCK_MONOTONIC_COARSE:   u64 = 6;
const CLOCK_BOOTTIME:           u64 = 7;

/// Wall-clock offset (ns since UNIX epoch) added to monotonic_ns
/// when callers ask for CLOCK_REALTIME. Starts at 0 (v1 has no RTC);
/// settimeofday / clock_settime overwrite it.
static REALTIME_OFFSET_NS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn monotonic_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

#[inline]
fn realtime_ns() -> u64 {
    monotonic_ns().wrapping_add(REALTIME_OFFSET_NS.load(Ordering::Acquire))
}

/// Pick the source ns based on POSIX `clk_id`. CLOCK_REALTIME and
/// _COARSE add the offset; everything else returns monotonic.
#[inline]
fn ns_for_clock(clk_id: u64) -> u64 {
    match clk_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => realtime_ns(),
        _ => monotonic_ns(),
    }
}

#[allow(dead_code)]
#[inline]
fn clock_id_known(clk_id: u64) -> bool {
    matches!(clk_id, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID | CLOCK_MONOTONIC_RAW
        | CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME)
}


/// `sys_clock_gettime(clk_id, tp)` — slot 228. Writes
/// `{tv_sec, tv_nsec}` for the given clock per `28§4`.
/// # C: O(1)
pub fn kernel_clock_gettime(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let tp = args.a1;
    if let Err(rv) = validate_user_buf(tp, 16, 8) { return rv; }
    let ns = ns_for_clock(clk_id);
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

/// `sys_settimeofday(tv, tz)` — slot 164. Writes REALTIME_OFFSET_NS
/// from `tv` so subsequent gettimeofday/time return wall-clock.
/// # C: O(1)
pub fn kernel_settimeofday(args: &SyscallArgs) -> i64 {
    let tv = args.a0;
    if tv == 0 || tv >= hal::USER_VA_END { return 0; }
    // SAFETY: tv validated 16-byte range; CPL=0 reads through caller's AS.
    let (sec, usec) = unsafe {
        let s = core::ptr::read_volatile(tv as *const u64);
        let u = core::ptr::read_volatile((tv + 8) as *const u64);
        (s, u)
    };
    let target = sec.saturating_mul(NS_PER_SEC).saturating_add(usec.saturating_mul(1000));
    REALTIME_OFFSET_NS.store(sched::clock::settimeofday_offset(monotonic_ns(), target), Ordering::Release);
    0
}

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

/// `sys_time(tloc)` — slot 201. Returns wall-clock seconds since
/// epoch (monotonic_ns + REALTIME_OFFSET_NS); writes *tloc.
/// # C: O(1)
pub fn kernel_time(args: &SyscallArgs) -> i64 {
    let sec = (realtime_ns() / NS_PER_SEC) as i64;
    let tloc = args.a0;
    if tloc != 0 && tloc < hal::USER_VA_END {
        // SAFETY: tloc validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe { core::ptr::write_volatile(tloc as *mut i64, sec); }
    }
    sec
}
