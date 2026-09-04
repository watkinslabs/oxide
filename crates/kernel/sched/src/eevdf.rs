//! Small, integer-only EEVDF policy primitives.
//!
//! The fair queue owns the runnable entities; this module owns the policy
//! arithmetic so eligibility and virtual deadlines cannot drift apart.

/// Return the virtual request length for a fair slice and a Linux load weight.
/// `weight` is the unshifted nice-table weight.
pub(crate) fn request_delta(slice: u64, weight: u64) -> u64 {
    let weight = weight.max(1) as u128;
    ((slice as u128).saturating_mul(1024) / weight).max(1).min(u64::MAX as u128) as u64
}

/// Linux's exact eligibility comparison, kept in product space to avoid the
/// precision loss from dividing the weighted average virtual runtime.
pub(crate) fn eligible(sum_w_vruntime: i128, total_weight: u128,
                        floor: u64, vruntime: u64) -> bool {
    if total_weight == 0 { return false; }
    sum_w_vruntime >= signed_delta(floor, vruntime) as i128 * total_weight as i128
}

/// Clamp lag to one virtual request, matching Linux's bounded EEVDF lag.
pub(crate) fn bounded_lag(sum_w_vruntime: i128, total_weight: u128,
                          floor: u64, vruntime: u64, limit: u64) -> i64 {
    if total_weight == 0 { return 0; }
    let avg_delta = sum_w_vruntime / total_weight as i128;
    let lag = avg_delta - signed_delta(floor, vruntime) as i128;
    lag.clamp(-(limit as i128), limit as i128) as i64
}

/// Signed clock subtraction within the scheduler's Linux-sized horizon.
fn signed_delta(floor: u64, value: u64) -> i64 {
    value.wrapping_sub(floor) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_delta_scales_inverse_to_weight() {
        assert_eq!(request_delta(4_000_000, 1024), 4_000_000);
        assert_eq!(request_delta(4_000_000, 2048), 2_000_000);
        assert_eq!(request_delta(4_000_000, 15), 273_066_666);
    }

    #[test]
    fn eligibility_uses_product_not_truncated_average() {
        assert!(eligible(3, 2, 0, 1));
        assert!(!eligible(1, 2, 0, 1));
    }

    #[test]
    fn lag_is_bounded_and_wrap_safe() {
        assert_eq!(bounded_lag(0, 1, u64::MAX - 2, 1, 10), -4);
        assert_eq!(bounded_lag(-100, 1, 0, 100, 10), -10);
    }
}
