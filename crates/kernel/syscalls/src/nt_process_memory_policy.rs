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

/// Write-side source probing follows Wine's native contract: an unreadable
/// input buffer is a partial copy with no completed bytes, not an access
/// violation from the output-buffer probe used by `NtReadVirtualMemory`.
/// # C: O(1)
pub fn write_source_fault_status(size: usize, source_valid: bool) -> Option<u64> {
    if size != 0 && !source_valid { Some(STATUS_PARTIAL_COPY) } else { None }
}

/// A current-process write must probe the NT destination's writable VMAs
/// before entering the transfer owner; a failed probe has no completed
/// prefix and therefore uses the same partial-copy result as a write fault.
/// # C: O(1)
pub fn write_destination_fault_status(size: usize, destination_valid: bool) -> Option<u64> {
    if size != 0 && !destination_valid { Some(STATUS_PARTIAL_COPY) } else { None }
}

/// Convert the native ABI's target/source pair into the owner's
/// source/destination pair; writes reverse the register order, reads do not.
/// # C: O(1)
pub fn copy_operands(read: bool, first: u64, second: u64) -> (u64, u64) {
    if read { (first, second) } else { (second, first) }
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

    #[test]
    fn write_probes_source_before_target_and_reports_partial_copy() {
        assert_eq!(write_source_fault_status(8, false), Some(STATUS_PARTIAL_COPY));
        assert_eq!(write_destination_fault_status(8, false), Some(STATUS_PARTIAL_COPY));
        assert_eq!(write_source_fault_status(0, false), None);
        assert_eq!(write_destination_fault_status(0, false), None);
    }

    #[test]
    fn write_owner_receives_native_source_then_target() {
        assert_eq!(copy_operands(true, 0x1000, 0x2000), (0x1000, 0x2000));
        assert_eq!(copy_operands(false, 0x1000, 0x2000), (0x2000, 0x1000));
    }
}
