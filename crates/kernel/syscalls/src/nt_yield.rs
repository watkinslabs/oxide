//! Native NT yield result policy, independent of the target-gated syscall shim.

const STATUS_SUCCESS: u64 = 0;
const STATUS_NO_YIELD_PERFORMED: u64 = 0x4000_0024;

/// Preserve the NT distinction between a scheduler round that switched away
/// and a round that immediately selected the caller again. # C: O(1)
pub fn status(before: (u64, u64), after: (u64, u64)) -> u64 {
    if before != after { STATUS_SUCCESS } else { STATUS_NO_YIELD_PERFORMED }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_context_switch_counters_report_no_yield() {
        assert_eq!(status((4, 7), (4, 7)), STATUS_NO_YIELD_PERFORMED);
    }

    #[test]
    fn voluntary_or_involuntary_switch_reports_success() {
        assert_eq!(status((4, 7), (5, 7)), STATUS_SUCCESS);
        assert_eq!(status((4, 7), (4, 8)), STATUS_SUCCESS);
    }
}
