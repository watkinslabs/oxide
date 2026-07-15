use sync::{Spinlock, Timer as TimerLock};

pub use crate::model::{ClockSnapshot, TimeError, MAX_TAI_OFFSET};
use crate::model::ClockState;

static CLOCK: Spinlock<ClockState, TimerLock> = Spinlock::new(ClockState::ZERO);

/// Snapshot canonical timekeeper adjustment state. # C: O(1)
pub fn snapshot() -> ClockSnapshot { CLOCK.lock().snapshot() }

/// Current CLOCK_REALTIME in Unix-epoch nanoseconds. # C: O(1)
pub fn realtime_ns() -> u64 { CLOCK.lock().realtime(crate::platform::monotonic_ns()) }

/// Current CLOCK_BOOTTIME including recorded suspend duration. # C: O(1)
pub fn boottime_ns() -> u64 { CLOCK.lock().boottime(crate::platform::monotonic_ns()) }

/// Current CLOCK_TAI using the independently owned TAI-UTC offset. # C: O(1)
pub fn tai_ns() -> u64 { CLOCK.lock().tai(crate::platform::monotonic_ns()) }

/// Step CLOCK_REALTIME without changing monotonic or boottime. # C: O(1)
pub fn set_realtime(target_ns: u64) {
    CLOCK.lock().set_realtime(crate::platform::monotonic_ns(), target_ns);
}

/// Seed CLOCK_REALTIME from a persistent clock. # C: O(1)
pub fn seed_realtime(target_ns: u64) { set_realtime(target_ns); }

/// Set the kernel TAI-UTC offset in seconds. # C: O(1)
pub fn set_tai_offset(seconds: i32) -> Result<(), TimeError> {
    CLOCK.lock().set_tai_offset(seconds)
}

/// Add one completed suspend interval to CLOCK_BOOTTIME. # C: O(1)
pub fn account_suspend(elapsed_ns: u64) { CLOCK.lock().account_suspend(elapsed_ns); }

/// Current TAI-UTC offset in seconds. # C: O(1)
pub fn tai_offset() -> i32 { CLOCK.lock().tai_offset_sec }

/// Clock-step generation for realtime absolute deadline consumers. # C: O(1)
pub fn realtime_generation() -> u64 { CLOCK.lock().realtime_generation }

/// Signed realtime-minus-monotonic offset, clamped to the legacy u64 ABI. # C: O(1)
pub fn realtime_offset_ns() -> u64 {
    CLOCK.lock().wall_offset_ns.clamp(0, u64::MAX as i128) as u64
}

/// Unix epoch seconds corresponding to monotonic zero. # C: O(1)
pub fn boot_unix_seconds() -> u64 { realtime_offset_ns() / 1_000_000_000 }
