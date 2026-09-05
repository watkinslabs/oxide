//! Hosted-testable admission and encoding for the native Windows Vulkan boundary.

pub(crate) const CAPABILITY_BYTES: usize = 24;
pub(crate) const CAPABILITY_VERSION: u32 = 1;
pub(crate) const FLAG_RENDER_NODE: u32 = 1;
pub(crate) const FLAG_3D: u32 = 2;
pub(crate) const STATUS_SUCCESS: u64 = 0;
pub(crate) const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
pub(crate) const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Facts { pub render_node: bool, pub three_d: bool, pub max_width: u32, pub max_height: u32, pub format_mask: u64 }

pub(crate) const fn query_status(length: usize, facts: Facts) -> u64 {
    if length != CAPABILITY_BYTES { STATUS_INFO_LENGTH_MISMATCH }
    else if !facts.render_node || !facts.three_d || facts.max_width == 0 || facts.max_height == 0 || facts.format_mask == 0 { STATUS_NOT_SUPPORTED }
    else { STATUS_SUCCESS }
}

pub(crate) fn encode(facts: Facts) -> [u8; CAPABILITY_BYTES] {
    let mut out = [0u8; CAPABILITY_BYTES];
    out[0..4].copy_from_slice(&CAPABILITY_VERSION.to_ne_bytes());
    out[4..8].copy_from_slice(&(if facts.render_node { FLAG_RENDER_NODE } else { 0 } | if facts.three_d { FLAG_3D } else { 0 }).to_ne_bytes());
    out[8..12].copy_from_slice(&facts.max_width.to_ne_bytes());
    out[12..16].copy_from_slice(&facts.max_height.to_ne_bytes());
    out[16..24].copy_from_slice(&facts.format_mask.to_ne_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Facts { Facts { render_node: true, three_d: true, max_width: 4096, max_height: 2160, format_mask: 3 } }

    #[test]
    fn capability_requires_exact_size_and_all_native_prerequisites() {
        assert_eq!(query_status(CAPABILITY_BYTES, valid()), STATUS_SUCCESS);
        assert_eq!(query_status(CAPABILITY_BYTES - 1, valid()), STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(query_status(CAPABILITY_BYTES, Facts { three_d: false, ..valid() }), STATUS_NOT_SUPPORTED);
        assert_eq!(query_status(CAPABILITY_BYTES, Facts { render_node: false, ..valid() }), STATUS_NOT_SUPPORTED);
        assert_eq!(query_status(CAPABILITY_BYTES, Facts { format_mask: 0, ..valid() }), STATUS_NOT_SUPPORTED);
    }

    #[test]
    fn encoding_publishes_one_versioned_fixed_width_record() {
        let out = encode(valid());
        assert_eq!(out.len(), CAPABILITY_BYTES);
        assert_eq!(u32::from_ne_bytes(out[0..4].try_into().unwrap()), CAPABILITY_VERSION);
        assert_eq!(u32::from_ne_bytes(out[4..8].try_into().unwrap()), FLAG_RENDER_NODE | FLAG_3D);
        assert_eq!(u64::from_ne_bytes(out[16..24].try_into().unwrap()), 3);
    }
}
