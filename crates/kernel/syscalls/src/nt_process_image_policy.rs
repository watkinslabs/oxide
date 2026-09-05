//! Hosted-testable encoding for the native process image-information query.

pub(crate) const BYTES: usize = 64;
const STATUS_SUCCESS: u64 = 0;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;

pub(crate) const fn length_status(length: usize) -> u64 {
    if length == BYTES { STATUS_SUCCESS } else { STATUS_INFO_LENGTH_MISMATCH }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Facts {
    pub transfer: u64,
    pub maximum_stack: u64,
    pub committed_stack: u64,
    pub subsystem: u32,
    pub subsystem_minor: u16,
    pub subsystem_major: u16,
    pub os_major: u16,
    pub os_minor: u16,
    pub image_characteristics: u16,
    pub dll_characteristics: u16,
    pub machine: u16,
    pub contains_code: bool,
    pub image_flags: u8,
    pub loader_flags: u32,
    pub image_size: u32,
    pub checksum: u32,
}

/// Encode the 64-bit `SECTION_IMAGE_INFORMATION` wire layout.
/// # C: O(1)
pub(crate) fn encode(facts: Facts) -> [u8; BYTES] {
    let mut out = [0u8; BYTES];
    out[0..8].copy_from_slice(&facts.transfer.to_ne_bytes());
    out[16..24].copy_from_slice(&facts.maximum_stack.to_ne_bytes());
    out[24..32].copy_from_slice(&facts.committed_stack.to_ne_bytes());
    out[32..36].copy_from_slice(&facts.subsystem.to_ne_bytes());
    out[36..38].copy_from_slice(&facts.subsystem_minor.to_ne_bytes());
    out[38..40].copy_from_slice(&facts.subsystem_major.to_ne_bytes());
    out[40..42].copy_from_slice(&facts.os_major.to_ne_bytes());
    out[42..44].copy_from_slice(&facts.os_minor.to_ne_bytes());
    out[44..46].copy_from_slice(&facts.image_characteristics.to_ne_bytes());
    out[46..48].copy_from_slice(&facts.dll_characteristics.to_ne_bytes());
    out[48..50].copy_from_slice(&facts.machine.to_ne_bytes());
    out[50] = facts.contains_code as u8;
    out[51] = facts.image_flags;
    out[52..56].copy_from_slice(&facts.loader_flags.to_ne_bytes());
    out[56..60].copy_from_slice(&facts.image_size.to_ne_bytes());
    out[60..64].copy_from_slice(&facts.checksum.to_ne_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_preserves_pe_header_facts_at_native_offsets() {
        let out = encode(Facts { transfer: 0x1400_1234, maximum_stack: 0x800000,
            committed_stack: 0x10000, subsystem: 3, subsystem_minor: 2, subsystem_major: 6,
            os_major: 10, os_minor: 0, image_characteristics: 0x22, dll_characteristics: 0x160,
            machine: 0x8664, contains_code: true, image_flags: 4, loader_flags: 7,
            image_size: 0x9000, checksum: 0x12345678 });
        assert_eq!(BYTES, 64);
        assert_eq!(u64::from_ne_bytes(out[0..8].try_into().unwrap()), 0x1400_1234);
        assert_eq!(u64::from_ne_bytes(out[16..24].try_into().unwrap()), 0x800000);
        assert_eq!(u16::from_ne_bytes(out[38..40].try_into().unwrap()), 6);
        assert_eq!(u16::from_ne_bytes(out[48..50].try_into().unwrap()), 0x8664);
        assert_eq!(out[50], 1);
        assert_eq!(out[51], 4);
        assert_eq!(u32::from_ne_bytes(out[56..60].try_into().unwrap()), 0x9000);
    }

    #[test]
    fn reserved_zero_bits_are_not_shadow_state() {
        let out = encode(Facts { transfer: 1, maximum_stack: 2, committed_stack: 3,
            subsystem: 4, subsystem_minor: 5, subsystem_major: 6, os_major: 7, os_minor: 8,
            image_characteristics: 9, dll_characteristics: 10, machine: 11, contains_code: false,
            image_flags: 12, loader_flags: 13, image_size: 14, checksum: 15 });
        assert_eq!(&out[8..16], &[0; 8]);
    }

    #[test]
    fn query_requires_the_exact_native_structure_size() {
        assert_eq!(length_status(BYTES), STATUS_SUCCESS);
        assert_eq!(length_status(BYTES - 1), STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(length_status(BYTES + 1), STATUS_INFO_LENGTH_MISMATCH);
    }
}
