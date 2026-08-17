//! Netlink attribute walking over one expression's data blob.

/// Attribute-type bits carrying the type itself; the top two select nesting
/// and byte order and are not part of the number.
const NLA_TYPE_MASK: u16 = 0x3fff;

/// # C: O(1)
pub fn align4(n: usize) -> usize { (n + 3) & !3 }

/// # C: O(1)
pub fn mask_nla(t: u16) -> u16 { t & NLA_TYPE_MASK }

/// Body of the first attribute of type `target`. # C: O(len(attrs))
pub fn find_bytes(attrs: &[u8], target: u16) -> Option<&[u8]> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]);
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if mask_nla(nla_type) == target { return Some(&attrs[off + 4..off + nla_len]); }
        off += align4(nla_len);
    }
    None
}

/// NUL-terminated string attribute. # C: O(len(attrs))
pub fn find_str(attrs: &[u8], target: u16) -> Option<&str> {
    let bytes = find_bytes(attrs, target)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).ok()
}

/// Network-order 32-bit attribute. # C: O(len(attrs))
pub fn find_u32_be(attrs: &[u8], target: u16) -> Option<u32> {
    let b = find_bytes(attrs, target)?;
    if b.len() < 4 { return None; }
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Network-order 64-bit attribute. # C: O(len(attrs))
pub fn find_u64_be(attrs: &[u8], target: u16) -> Option<u64> {
    let b = find_bytes(attrs, target)?;
    if b.len() < 8 { return None; }
    Some(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Network-order 16-bit attribute. # C: O(len(attrs))
pub fn find_u16_be(attrs: &[u8], target: u16) -> Option<u16> {
    let b = find_bytes(attrs, target)?;
    if b.len() < 2 { return None; }
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// Single-byte attribute. # C: O(len(attrs))
pub fn find_u8(attrs: &[u8], target: u16) -> Option<u8> {
    find_bytes(attrs, target).and_then(|b| b.first().copied())
}

/// Value bytes of a nested `NFTA_DATA_VALUE` attribute. # C: O(len(attrs))
pub fn find_data_value(attrs: &[u8], target: u16) -> Option<&[u8]> {
    use crate::nft_expr::uapi::NFTA_DATA_VALUE;
    find_bytes(find_bytes(attrs, target)?, NFTA_DATA_VALUE)
}
