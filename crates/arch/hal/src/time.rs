const NS_PER_MS: u64 = 1_000_000;

/// Convert an architecture counter at `khz` to nanoseconds without overflowing
/// the intermediate multiplication.
/// # C: O(1)
pub const fn counter_ns(counter: u64, khz: u32) -> u64 {
    if khz == 0 { return 0; }
    let divisor = khz as u64;
    let whole = counter / divisor;
    let remainder = counter % divisor;
    whole.wrapping_mul(NS_PER_MS)
        .wrapping_add(remainder * NS_PER_MS / divisor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_matches_wide_arithmetic_across_boundaries() {
        for khz in [1, 24_000, 50_000, 1_000_000, u32::MAX] {
            for counter in [0, 1, khz as u64 - 1, khz as u64,
                u64::MAX / NS_PER_MS, u64::MAX]
            {
                let expected = ((counter as u128 * NS_PER_MS as u128 / khz as u128)
                    & u64::MAX as u128) as u64;
                assert_eq!(counter_ns(counter, khz), expected);
            }
        }
    }

    #[test]
    fn zero_frequency_returns_zero() {
        assert_eq!(counter_ns(u64::MAX, 0), 0);
    }
}
