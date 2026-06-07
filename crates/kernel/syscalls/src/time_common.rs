// time_common — helpers shared by ≥2 time syscall handlers (docs/53 §0).
// Moved verbatim from time.rs.
//
// Real CLOCK_REALTIME tracking: monotonic_ns + REALTIME_OFFSET_NS
// (settable via settimeofday / clock_settime CLOCK_REALTIME). v1
// has no RTC at boot — the offset starts at 0, callers can set it.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};

use hal::TimerOps;

pub(crate) const NS_PER_SEC: u64 = 1_000_000_000;

pub(crate) const CLOCK_REALTIME:           u64 = 0;
pub(crate) const CLOCK_MONOTONIC:          u64 = 1;
pub(crate) const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
pub(crate) const CLOCK_THREAD_CPUTIME_ID:  u64 = 3;
pub(crate) const CLOCK_MONOTONIC_RAW:      u64 = 4;
pub(crate) const CLOCK_REALTIME_COARSE:    u64 = 5;
pub(crate) const CLOCK_MONOTONIC_COARSE:   u64 = 6;
pub(crate) const CLOCK_BOOTTIME:           u64 = 7;

/// Wall-clock offset (ns since UNIX epoch) added to monotonic_ns
/// when callers ask for CLOCK_REALTIME. Starts at 0 (v1 has no RTC);
/// settimeofday / clock_settime overwrite it.
pub(crate) static REALTIME_OFFSET_NS: AtomicU64 = AtomicU64::new(0);

/// # C: O(1)
#[inline]
pub(crate) fn monotonic_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// # C: O(1)
#[inline]
pub(crate) fn realtime_ns() -> u64 {
    monotonic_ns().wrapping_add(REALTIME_OFFSET_NS.load(Ordering::Acquire))
}

/// Pick the source ns based on POSIX `clk_id`. CLOCK_REALTIME and
/// _COARSE add the offset; everything else returns monotonic.
/// # C: O(1)
#[inline]
pub(crate) fn ns_for_clock(clk_id: u64) -> u64 {
    match clk_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => realtime_ns(),
        _ => monotonic_ns(),
    }
}

/// # C: O(1)
#[allow(dead_code)]
#[inline]
pub(crate) fn clock_id_known(clk_id: u64) -> bool {
    matches!(clk_id, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID | CLOCK_MONOTONIC_RAW
        | CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME)
}
