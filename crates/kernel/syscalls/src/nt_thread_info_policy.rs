//! Hosted-testable policy for the native thread-information affinity class.

use cpu::CpuMask;

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_SUCCESS: u64 = 0;

/// Validate one Windows `ThreadAffinityMask` before scheduler publication.
/// # C: O(words)
pub fn affinity(want: CpuMask, process: CpuMask, active: CpuMask, no_setaffinity: bool) -> Result<CpuMask, u64> {
    if no_setaffinity || want.is_empty() || !want.is_subset_of(process)
        || !want.is_subset_of(active) { return Err(STATUS_INVALID_PARAMETER); }
    Ok(want)
}

/// Preserve the native success value as a named policy result for adapter tests.
/// # C: O(1)
pub const fn success() -> u64 { STATUS_SUCCESS }

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(bits: u64) -> CpuMask { CpuMask::from_words(&[bits]) }

    #[test]
    fn affinity_accepts_a_nonempty_process_subset_unchanged() {
        assert_eq!(affinity(mask(0b0011), mask(0b1011), mask(0b1111), false), Ok(mask(0b0011)));
    }

    #[test]
    fn affinity_rejects_bits_outside_the_process_mask() {
        assert_eq!(affinity(mask(0b0100), mask(0b0011), mask(0b1111), false), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn affinity_rejects_empty_mask() {
        assert_eq!(affinity(mask(0), mask(0b0011), mask(0b1111), false), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn affinity_rejects_structurally_unmodifiable_threads() {
        assert_eq!(affinity(mask(1), mask(1), mask(1), true), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn positive_control_rejects_a_mask_the_old_unchecked_path_would_publish() {
        let requested = mask(0b0101);
        let process = mask(0b0011);
        assert!(affinity(requested, process, CpuMask::all(), false).is_err());
    }
}
