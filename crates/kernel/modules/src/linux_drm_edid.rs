//! DRM base-EDID header validation.

use super::*;

const EDID_HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];

pub(super) fn export_symbols() { crate::symtab::export("drm_edid_header_is_valid", drm_edid_header_is_valid as *const () as usize, false); }

/// Score matching bytes in a raw base-EDID header. # C: O(8)
pub(super) extern "C" fn drm_edid_header_is_valid(edid: *const c_void) -> i32 {
    if edid.is_null() { return 0; }
    // SAFETY: the external EDID caller provides at least the fixed eight-byte base header.
    let bytes = unsafe { core::slice::from_raw_parts(edid.cast::<u8>(), EDID_HEADER.len()) };
    bytes.iter().zip(EDID_HEADER).filter(|(got, expected)| **got == *expected).count() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_score_counts_each_matching_byte() {
        let mut header = EDID_HEADER; assert_eq!(drm_edid_header_is_valid(header.as_ptr().cast()), 8);
        header[2] = 0; header[7] = 0xff; assert_eq!(drm_edid_header_is_valid(header.as_ptr().cast()), 6);
        assert_eq!(drm_edid_header_is_valid(core::ptr::null()), 0);
    }

    #[test]
    fn header_validator_is_a_module_export() { let _modules = crate::test_serial::claim(); export_symbols(); assert!(crate::symtab::is_exported("drm_edid_header_is_valid")); }
}
