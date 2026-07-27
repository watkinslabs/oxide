//! System timekeeper manifest.
//! - `model`: deterministic realtime, boottime, and TAI state transitions.
//! - `platform`: architecture monotonic-clock sampling.
//! - `state`: canonical synchronized clock providers and adjustment API.
//! - `ntp`: NTP discipline state and the `adjtimex(2)` transaction.

#![no_std]

mod model;
mod platform;
mod state;
pub mod ntp;

pub use platform::monotonic_ns;
pub use state::{account_suspend, boottime_ns, boot_unix_seconds, inject_offset,
    realtime_generation, realtime_ns, realtime_offset_ns, seed_realtime, set_realtime,
    set_tai_offset, slew_realtime, snapshot, tai_ns, tai_offset, ClockSnapshot, TimeError,
    MAX_TAI_OFFSET};
