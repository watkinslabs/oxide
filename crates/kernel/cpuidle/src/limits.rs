// Bounds and unit conversions.

/// Most idle states one driver may declare.
pub const MAX_STATES: usize = 10;

/// Nanoseconds per microsecond. Drivers and firmware declare latency and
/// residency in microseconds; every decision here is made in nanoseconds,
/// because a microsecond-granular comparison against a residency of a few
/// microseconds is most of the answer thrown away.
pub const NSEC_PER_USEC: u64 = 1_000;

/// A measured residency below this is a short idle: the CPU woke almost
/// immediately, and a governor counts that against going deeper next time.
pub const RESIDENCY_THRESHOLD_NS: u64 = 15 * NSEC_PER_USEC;

/// Below this latency requirement a governor stops looking at anything but
/// the shallowest states.
pub const LATENCY_THRESHOLD_NS: u64 = RESIDENCY_THRESHOLD_NS / 2;

/// Longest sleep a governor treats as meaningful when correcting its own
/// prediction. Anything beyond it is "a long time" and carries no more
/// information than that.
pub const MAX_INTERESTING_NS: u64 = 50_000 * NSEC_PER_USEC;

/// No latency requirement at all.
pub const LATENCY_UNLIMITED_NS: u64 = u64::MAX;

/// Microseconds from nanoseconds, truncating, as every duration attribute
/// reports. # C: O(1)
pub fn ns_to_us(ns: u64) -> u64 { ns / NSEC_PER_USEC }

/// Nanoseconds from microseconds, saturating. # C: O(1)
pub fn us_to_ns(us: u64) -> u64 { us.saturating_mul(NSEC_PER_USEC) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_unit_conversions_are_inverse_at_microsecond_granularity() {
        assert_eq!(us_to_ns(1), 1_000);
        assert_eq!(ns_to_us(1_000), 1);
        assert_eq!(ns_to_us(1_999), 1, "truncates rather than rounding");
        assert_eq!(ns_to_us(999), 0);
        for us in [0u64, 1, 7, 1_000, 1_000_000] {
            assert_eq!(ns_to_us(us_to_ns(us)), us);
        }
    }

    #[test]
    fn a_microsecond_declaration_is_not_mistaken_for_a_nanosecond_one() {
        // A driver declaring 10 us of exit latency must not be read as 10 ns:
        // that is a thousand-fold understatement and would let a governor
        // choose a state whose wakeup cost swamps the sleep.
        assert_eq!(us_to_ns(10), 10_000);
        assert_ne!(us_to_ns(10), 10);
    }

    #[test]
    fn the_thresholds_sit_where_the_governors_expect_them() {
        assert_eq!(RESIDENCY_THRESHOLD_NS, 15_000);
        assert_eq!(LATENCY_THRESHOLD_NS, 7_500);
        assert_eq!(MAX_INTERESTING_NS, 50_000_000);
        assert!(LATENCY_THRESHOLD_NS < RESIDENCY_THRESHOLD_NS);
    }
}
