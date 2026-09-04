//! ProcessVmCounters ABI encoding shared by the native process adapter.

pub(crate) const CLASS: u32 = 3;
pub(crate) const BYTES: usize = 88;
pub(crate) const EX_BYTES: usize = 96;

/// Encode the x86-64/ARM64 `VM_COUNTERS_EX` shape from the owning mm facts.
/// # C: O(1)
pub(crate) fn encode(accounting: &vmm::VmAccountingSnapshot) -> [u8; EX_BYTES] {
    let page = hal::PAGE_SIZE_BYTES;
    let bytes = |pages: u64| pages.saturating_mul(page);
    let mut out = [0u8; EX_BYTES];
    out[0..8].copy_from_slice(&accounting.peak_virtual_bytes.to_ne_bytes());
    out[8..16].copy_from_slice(&accounting.virtual_bytes.to_ne_bytes());
    out[16..20].copy_from_slice(&(accounting.faults.min(u32::MAX as u64) as u32).to_ne_bytes());
    out[24..32].copy_from_slice(&bytes(accounting.hiwater_rss_pages).to_ne_bytes());
    out[32..40].copy_from_slice(&bytes(accounting.rss_pages().total()).to_ne_bytes());
    let rss = accounting.rss_pages();
    let pagefile = bytes(rss.anon.saturating_add(rss.swapents));
    out[72..80].copy_from_slice(&pagefile.to_ne_bytes());
    out[80..88].copy_from_slice(&pagefile.to_ne_bytes());
    out[88..96].copy_from_slice(&pagefile.to_ne_bytes());
    out
}

pub(crate) const fn required_length(length: usize) -> usize {
    if length == BYTES { BYTES } else { EX_BYTES }
}

pub(crate) const fn valid_length(length: usize) -> bool {
    length == BYTES || length == EX_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_sizes_and_length_rules_match_native_shape() {
        assert_eq!(BYTES, 88);
        assert_eq!(EX_BYTES, 96);
        assert!(!valid_length(87));
        assert!(valid_length(BYTES));
        assert!(valid_length(EX_BYTES));
        assert!(!valid_length(97));
        assert_eq!(required_length(89), EX_BYTES);
    }

    #[test]
    fn encoding_uses_mm_facts_and_keeps_reserved_quota_zero() {
        let accounting = vmm::VmAccountingSnapshot {
            virtual_bytes: 0x2000,
            peak_virtual_bytes: 0x4000,
            faults: u64::from(u32::MAX) + 1,
            anon_pte_mappings: 3,
            swap_pte_mappings: 2,
            hiwater_rss_pages: 7,
            ..Default::default()
        };
        let out = encode(&accounting);
        assert_eq!(u64::from_ne_bytes(out[0..8].try_into().unwrap()), 0x4000);
        assert_eq!(u64::from_ne_bytes(out[8..16].try_into().unwrap()), 0x2000);
        assert_eq!(u32::from_ne_bytes(out[16..20].try_into().unwrap()), u32::MAX);
        assert_eq!(u64::from_ne_bytes(out[24..32].try_into().unwrap()), 7 * hal::PAGE_SIZE_BYTES);
        assert_eq!(u64::from_ne_bytes(out[32..40].try_into().unwrap()), 3 * hal::PAGE_SIZE_BYTES);
        assert_eq!(u64::from_ne_bytes(out[72..80].try_into().unwrap()), 5 * hal::PAGE_SIZE_BYTES);
        assert!(out[40..72].iter().all(|byte| *byte == 0));
        assert_eq!(u64::from_ne_bytes(out[80..88].try_into().unwrap()), 5 * hal::PAGE_SIZE_BYTES);
        assert_eq!(u64::from_ne_bytes(out[88..96].try_into().unwrap()), 5 * hal::PAGE_SIZE_BYTES);
    }
}
