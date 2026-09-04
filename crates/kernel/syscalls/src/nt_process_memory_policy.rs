//! Untargeted NT process-memory result policy.

pub const STATUS_SUCCESS: u64 = 0;
pub const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
pub const STATUS_PARTIAL_COPY: u64 = 0x8000_000d;

/// The Windows read path validates the caller's destination before attempting
/// to inspect the source. A source fault is a partial copy; a destination
/// fault is an access violation and cannot be reported as partial progress.
/// # C: O(1)
pub fn destination_fault_status(size: usize, destination_valid: bool) -> Option<u64> {
    if size != 0 && !destination_valid { Some(STATUS_ACCESS_VIOLATION) } else { None }
}

/// Map an owner transfer count to the NT result while preserving the count
/// already committed by earlier successful chunks.
/// # C: O(1)
pub fn completion_status(requested: usize, copied: usize) -> u64 {
    if copied == requested { STATUS_SUCCESS } else { STATUS_PARTIAL_COPY }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_fault_precedes_source_and_is_not_partial() {
        assert_eq!(destination_fault_status(12, false), Some(STATUS_ACCESS_VIOLATION));
        assert_eq!(completion_status(12, 0), STATUS_PARTIAL_COPY);
    }

    #[test]
    fn zero_length_copy_does_not_require_a_destination() {
        assert_eq!(destination_fault_status(0, false), None);
        assert_eq!(completion_status(0, 0), STATUS_SUCCESS);
    }

    #[test]
    fn completed_prefix_is_reported_as_partial() {
        assert_eq!(completion_status(8192, 4096), STATUS_PARTIAL_COPY);
        assert_eq!(completion_status(8192, 8192), STATUS_SUCCESS);
    }
}
