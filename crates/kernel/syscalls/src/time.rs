// Time-shaped syscalls. Handlers split per-file (docs/53 §0):
//   clock_gettime  → 228_clock_gettime.rs
//   clock_getres   → 229_clock_getres.rs
//   clock_settime  → 227_clock_settime.rs
//   gettimeofday   → 096_gettimeofday.rs
//   settimeofday   → 164_settimeofday.rs
//   time           → 201_time.rs
//   adjtimex       → 159_adjtimex.rs
//   clock_adjtime  → 305_clock_adjtime.rs
// Shared helpers live in time_common.rs. This file keeps the
// non-handler wall-clock accessors + re-exports for callers.

#![cfg(target_os = "oxide-kernel")]

pub use crate::s228_clock_gettime::kernel_clock_gettime;
pub use crate::s229_clock_getres::kernel_clock_getres;
pub use crate::s227_clock_settime::kernel_clock_settime;
pub use crate::s096_gettimeofday::kernel_gettimeofday;
pub use crate::s164_settimeofday::kernel_settimeofday;
pub use crate::s201_time::kernel_time;
pub use crate::s159_adjtimex::sys_adjtimex as kernel_adjtimex;
pub use crate::s305_clock_adjtime::sys_clock_adjtime as kernel_clock_adjtime;

/// Seconds since the Unix epoch at which the kernel started, derived
/// from the canonical timekeeper state.
/// Returns 0 until userspace seeds the wall clock — Linux's `btime`
/// reports 0 in the same situation.
/// # C: O(1)
pub fn boot_unix_seconds() -> u64 {
    timekeeper::boot_unix_seconds()
}

/// CLOCK_REALTIME offset (ns since the Unix epoch added to monotonic).
/// Read by the vvar publisher so the vDSO realtime snapshot matches the
/// syscall path. # C: O(1)
pub fn realtime_offset_ns() -> u64 {
    timekeeper::realtime_offset_ns()
}
