// Time-shaped syscalls. Handlers split per-file (docs/53 §0):
//   clock_gettime  → 228_clock_gettime.rs
//   clock_getres   → 229_clock_getres.rs
//   clock_settime  → 227_clock_settime.rs
//   gettimeofday   → 096_gettimeofday.rs
//   settimeofday   → 164_settimeofday.rs
//   time           → 201_time.rs
// Shared helpers live in time_common.rs. This file keeps the
// non-handler wall-clock accessors + re-exports for callers.
//
// Real CLOCK_REALTIME tracking: monotonic_ns + REALTIME_OFFSET_NS
// (settable via settimeofday / clock_settime CLOCK_REALTIME). v1
// has no RTC at boot — the offset starts at 0, callers can set it.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use crate::time_common::REALTIME_OFFSET_NS;

pub use crate::s228_clock_gettime::kernel_clock_gettime;
pub use crate::s229_clock_getres::kernel_clock_getres;
pub use crate::s227_clock_settime::kernel_clock_settime;
pub use crate::s096_gettimeofday::kernel_gettimeofday;
pub use crate::s164_settimeofday::kernel_settimeofday;
pub use crate::s201_time::kernel_time;

/// Seconds since the Unix epoch at which the kernel started, derived
/// from `REALTIME_OFFSET_NS` (set by `settimeofday` / `clock_settime`).
/// Returns 0 until userspace seeds the wall clock — Linux's `btime`
/// reports 0 in the same situation.
/// # C: O(1)
pub fn boot_unix_seconds() -> u64 {
    REALTIME_OFFSET_NS.load(Ordering::Acquire) / 1_000_000_000
}

/// CLOCK_REALTIME offset (ns since the Unix epoch added to monotonic).
/// Read by the vvar publisher so the vDSO realtime snapshot matches the
/// syscall path. # C: O(1)
pub fn realtime_offset_ns() -> u64 {
    REALTIME_OFFSET_NS.load(Ordering::Acquire)
}
