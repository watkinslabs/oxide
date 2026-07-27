// Shared fixture for the NTP discipline tests. Split per docs/08§7: tests count
// toward the file cap, and one file per behaviour group keeps each readable.

use super::super::model::{NtpState, Timex};

/// A freshly initialised, undisciplined clock with its tick length derived.
pub(super) fn nominal() -> NtpState {
    let mut n = NtpState::INIT;
    n.update_frequency();
    n.tick_length = n.tick_length_base;
    n
}

/// A zeroed `timex` — `modes == 0` is the read-only query every NTP client
/// opens with.
pub(super) fn query() -> Timex { Timex::default() }
