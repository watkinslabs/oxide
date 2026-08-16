// Bounds and cadences the thermal core enforces.

/// Longest zone or cooling-device type string a provider may declare.
pub const NAME_LEN: usize = 20;

/// Delay before re-reading a zone whose sensor just failed.
pub const RECHECK_DELAY_MS: u64 = 250;

/// A zone whose recheck backoff grows past this is broken, not busy, and is
/// disabled instead of being polled forever.
pub const MAX_RECHECK_DELAY_MS: u64 = 120_000;

/// Milliseconds in a second, for the deci-second cadences firmware reports in.
pub const MSEC_PER_SEC: u64 = 1_000;

/// Nanoseconds per millisecond; the poll deadlines are monotonic nanoseconds.
pub const NSEC_PER_MSEC: u64 = 1_000_000;

/// Grow the recheck backoff by half, never by less than one unit, so a sensor
/// that keeps failing stops being read every quarter second forever.
/// # C: O(1)
pub fn grow_recheck_delay(current_ms: u64) -> u64 {
    current_ms.saturating_add((current_ms >> 1).max(1))
}

/// Whether a backoff has grown past the point where the zone is declared
/// broken. # C: O(1)
pub fn recheck_exhausted(delay_ms: u64) -> bool { delay_ms > MAX_RECHECK_DELAY_MS }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_grows_by_half_and_always_advances() {
        assert_eq!(grow_recheck_delay(250), 375);
        assert_eq!(grow_recheck_delay(375), 562);
        assert_eq!(grow_recheck_delay(1), 2, "a one-unit delay must still advance");
        assert_eq!(grow_recheck_delay(0), 1, "a zero delay must not stall the backoff");
    }

    #[test]
    fn a_backoff_reaching_two_minutes_declares_the_sensor_broken() {
        assert!(!recheck_exhausted(RECHECK_DELAY_MS));
        assert!(!recheck_exhausted(MAX_RECHECK_DELAY_MS));
        assert!(recheck_exhausted(MAX_RECHECK_DELAY_MS + 1));
    }

    #[test]
    fn the_backoff_reaches_its_ceiling_in_a_bounded_number_of_failures() {
        let mut delay = RECHECK_DELAY_MS;
        let mut steps = 0;
        while !recheck_exhausted(delay) { delay = grow_recheck_delay(delay); steps += 1; }
        assert!(steps > 5 && steps < 30, "unexpected backoff length: {steps}");
    }
}
