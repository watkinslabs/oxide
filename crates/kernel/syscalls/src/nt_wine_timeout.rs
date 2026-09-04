//! Wine server deadline conversion at the NT wait boundary.

/// Convert a Wine server timeout into the signed NT timeout representation.
/// Wine uses positive Windows-epoch deadlines and negative monotonic deadlines.
pub(crate) fn to_nt_timeout(raw: u64, monotonic_ns: u64, infinite: u64) -> Result<Option<i64>, ()> {
    if raw == infinite { return Ok(None); }
    let value = raw as i64;
    if value >= 0 { return Ok(Some(value)); }
    let deadline = value.checked_neg().ok_or(())? as u64;
    let now = monotonic_ns / 100;
    let remaining = deadline.saturating_sub(now);
    Ok(Some(-(remaining as i64)))
}

#[cfg(test)]
mod tests {
    use super::to_nt_timeout;

    const INFINITE: u64 = 0x7fff_ffff_ffff_ffff;

    #[test]
    fn preserves_absolute_windows_deadlines() {
        assert_eq!(to_nt_timeout(133_444_736_000_000_000, 9_000, INFINITE), Ok(Some(133_444_736_000_000_000)));
    }

    #[test]
    fn translates_server_monotonic_deadlines_to_relative_nt_time() {
        assert_eq!(to_nt_timeout((-25_000i64) as u64, 1_000_000, INFINITE), Ok(Some(-15_000)));
    }

    #[test]
    fn expired_server_deadline_becomes_zero_relative_timeout() {
        assert_eq!(to_nt_timeout((-10_000i64) as u64, 2_000_000, INFINITE), Ok(Some(0)));
    }

    #[test]
    fn preserves_infinite_wait_without_a_timeout_pointer() {
        assert_eq!(to_nt_timeout(INFINITE, 0, INFINITE), Ok(None));
    }

    #[test]
    fn rejects_unrepresentable_timeout_values() {
        assert_eq!(to_nt_timeout(i64::MIN as u64, 0, INFINITE), Err(()));
    }
}
