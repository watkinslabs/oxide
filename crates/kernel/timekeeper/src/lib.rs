//! System timekeeper manifest.
//! - `model`: deterministic realtime, boottime, and TAI state transitions.
//! - `platform`: architecture monotonic-clock sampling.
//! - `state`: canonical synchronized clock providers and adjustment API.

#![no_std]

mod model;
mod platform;
mod state;

pub use platform::monotonic_ns;
pub use state::{account_suspend, boottime_ns, boot_unix_seconds, realtime_generation,
    realtime_ns, realtime_offset_ns, seed_realtime, set_realtime, set_tai_offset,
    snapshot, tai_ns, tai_offset, ClockSnapshot, TimeError, MAX_TAI_OFFSET};
