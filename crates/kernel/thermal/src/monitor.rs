// When a zone is read again. Two cadences: the ordinary one, and a faster one
// used while a passive trip is engaged, because a zone that is actively being
// throttled is the one whose temperature is moving. A sensor that fails backs
// off instead, and a sensor that keeps failing is disabled rather than polled
// forever.

use crate::limits::{grow_recheck_delay, recheck_exhausted, RECHECK_DELAY_MS};

/// The two declared cadences of one zone, in milliseconds. Zero means the
/// zone is not polled on that cadence.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cadence { pub polling_ms: u64, pub passive_ms: u64 }

impl Cadence {
    /// A zone polled at one rate with no separate throttled rate. # C: O(1)
    pub fn polled(polling_ms: u64) -> Cadence { Cadence { polling_ms, passive_ms: 0 } }
}

/// Delay before the next read of a zone whose last read succeeded, or `None`
/// when the zone is purely event-driven. # C: O(1)
pub fn next_delay_ms(cadence: Cadence, passive_engaged: usize) -> Option<u64> {
    if passive_engaged > 0 && cadence.passive_ms != 0 { return Some(cadence.passive_ms); }
    if cadence.polling_ms != 0 { return Some(cadence.polling_ms); }
    None
}

/// What to do after a failed sensor read.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Recheck {
    /// Read again after this many milliseconds, with the backoff now at
    /// `next_backoff_ms`.
    Retry { delay_ms: u64, next_backoff_ms: u64 },
    /// The sensor has failed for long enough to be broken. The zone is
    /// disabled and its backoff reset, so re-enabling it starts fresh.
    Broken,
}

/// A read that reported the value is not ready yet is not a failure: it
/// retries at the fixed cadence and never grows the backoff, because a sensor
/// that is merely slow must not end up disabled.
pub const NOT_READY_DELAY_MS: u64 = RECHECK_DELAY_MS;

/// Decide the response to a failed read. `not_ready` distinguishes "ask again
/// shortly" from a real error. # C: O(1)
pub fn on_read_failure(backoff_ms: u64, not_ready: bool) -> Recheck {
    if not_ready {
        return Recheck::Retry { delay_ms: NOT_READY_DELAY_MS, next_backoff_ms: backoff_ms };
    }
    if recheck_exhausted(backoff_ms) { return Recheck::Broken; }
    Recheck::Retry { delay_ms: backoff_ms, next_backoff_ms: grow_recheck_delay(backoff_ms) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::MAX_RECHECK_DELAY_MS;

    #[test]
    fn an_engaged_passive_trip_selects_the_faster_cadence() {
        let cadence = Cadence { polling_ms: 4_000, passive_ms: 1_000 };
        assert_eq!(next_delay_ms(cadence, 0), Some(4_000));
        assert_eq!(next_delay_ms(cadence, 1), Some(1_000));
        assert_eq!(next_delay_ms(cadence, 3), Some(1_000),
                   "any engaged passive trip is enough; the count is not a multiplier");
    }

    #[test]
    fn a_zone_with_no_passive_cadence_keeps_its_ordinary_one() {
        let cadence = Cadence::polled(4_000);
        assert_eq!(next_delay_ms(cadence, 2), Some(4_000));
    }

    #[test]
    fn an_event_driven_zone_is_not_polled_at_all() {
        assert_eq!(next_delay_ms(Cadence { polling_ms: 0, passive_ms: 0 }, 0), None);
        assert_eq!(next_delay_ms(Cadence { polling_ms: 0, passive_ms: 0 }, 1), None);
        assert_eq!(next_delay_ms(Cadence { polling_ms: 0, passive_ms: 500 }, 1), Some(500),
                   "a throttled zone still needs watching even with no ordinary cadence");
    }

    #[test]
    fn a_sensor_that_is_not_ready_retries_without_growing_the_backoff() {
        let outcome = on_read_failure(RECHECK_DELAY_MS, true);
        assert_eq!(outcome, Recheck::Retry {
            delay_ms: NOT_READY_DELAY_MS, next_backoff_ms: RECHECK_DELAY_MS,
        });
        // Repeating it forever must never reach Broken.
        let mut backoff = RECHECK_DELAY_MS;
        for _ in 0..1_000 {
            match on_read_failure(backoff, true) {
                Recheck::Retry { next_backoff_ms, .. } => backoff = next_backoff_ms,
                Recheck::Broken => panic!("a slow sensor was declared broken"),
            }
        }
    }

    #[test]
    fn a_failing_sensor_backs_off_and_is_eventually_declared_broken() {
        let mut backoff = RECHECK_DELAY_MS;
        let mut reads = 0;
        loop {
            match on_read_failure(backoff, false) {
                Recheck::Retry { delay_ms, next_backoff_ms } => {
                    assert_eq!(delay_ms, backoff);
                    assert!(next_backoff_ms > backoff);
                    backoff = next_backoff_ms;
                    reads += 1;
                    assert!(reads < 100, "the backoff never terminated");
                }
                Recheck::Broken => break,
            }
        }
        assert!(backoff > MAX_RECHECK_DELAY_MS);
    }
}
