//! Native system-time ABI policy shared by the target handler and hosted tests.

const TICKS_PER_SECOND: i128 = 10_000_000;
const HALF_SECOND: i128 = TICKS_PER_SECOND / 2;

pub(crate) const NT_EPOCH_100NS: u64 = 116_444_736_000_000_000;
pub(crate) const STATUS_SUCCESS: u64 = 0;
pub(crate) const STATUS_PRIVILEGE_NOT_HELD: u64 = 0xc000_0061;

/// Convert the canonical Unix nanosecond clock to an NT `LARGE_INTEGER`.
/// # C: O(1)
pub(crate) fn unix_ns_to_nt_100ns(unix_ns: u64) -> u64 {
    NT_EPOCH_100NS.saturating_add(unix_ns / 100)
}

/// Apply Wine's native time-set decision: small corrections succeed without
/// stepping the host clock; larger corrections require the missing privilege.
/// # C: O(1)
pub(crate) fn set_status(now: u64, requested: u64) -> u64 {
    let diff = i128::from(requested) - i128::from(now);
    if diff > -HALF_SECOND && diff < HALF_SECOND { STATUS_SUCCESS }
    else { STATUS_PRIVILEGE_NOT_HELD }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_epoch_conversion_preserves_100ns_units() {
        assert_eq!(unix_ns_to_nt_100ns(0), NT_EPOCH_100NS);
        assert_eq!(unix_ns_to_nt_100ns(1_234_567_890), NT_EPOCH_100NS + 12_345_678);
    }

    #[test]
    fn strict_half_second_window_matches_native_contract() {
        let now = NT_EPOCH_100NS + 10_000_000_000;
        assert_eq!(set_status(now, now + 4_999_999), STATUS_SUCCESS);
        assert_eq!(set_status(now, now - 4_999_999), STATUS_SUCCESS);
        assert_eq!(set_status(now, now + 5_000_000), STATUS_PRIVILEGE_NOT_HELD);
        assert_eq!(set_status(now, now - 5_000_000), STATUS_PRIVILEGE_NOT_HELD);
    }
}
