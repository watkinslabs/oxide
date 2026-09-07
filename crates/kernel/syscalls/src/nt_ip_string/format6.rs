//! IPv6 address formatting: longest zero-run elision, the embedded dotted
//! quad, and the bracketed scope and port forms.

use super::ipv4;

const ADDRESS_BYTES: usize = 16;
const ADDRESS_WORDS: usize = 8;
/// Words before an embedded dotted quad.
const EMBEDDED_IPV4_WORDS: usize = 6;
/// The tunnel prefix word that also selects the embedded quad form.
const ISATAP_MARKER: u16 = 0x5efe;
const ISATAP_IGNORED_BITS: u16 = 0x0200;
const MAPPED_MARKER: u16 = 0xffff;
const COLON: u8 = b':';
const PERCENT: u8 = b'%';
const OPEN_BRACKET: u8 = b'[';
const CLOSE_BRACKET: u8 = b']';
/// The reference's formatting scratch, which bounds every produced address.
pub(crate) const TEXT_BYTES: usize = 64;
/// The fixed buffer size the non-extended formatters assume.
pub(crate) const PLAIN_TEXT_BYTES: u32 = 46;

fn word(bytes: &[u8; ADDRESS_BYTES], index: usize) -> u16 { u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]) }

/// Whether the low words carry an address that prints as a dotted quad.
/// # C: O(1)
fn is_ipv4_in_ipv6(bytes: &[u8; ADDRESS_BYTES]) -> bool {
    if word(bytes, 5) == ISATAP_MARKER && word(bytes, 4) & !ISATAP_IGNORED_BITS == 0 { return true; }
    if bytes[..8].iter().any(|byte| *byte != 0) { return false; }
    if word(bytes, 4) != 0 && word(bytes, 4) != MAPPED_MARKER { return false; }
    if word(bytes, 4) == 0 && word(bytes, 5) != 0 && word(bytes, 5) != MAPPED_MARKER { return false; }
    if word(bytes, 4) == MAPPED_MARKER && word(bytes, 5) != 0 { return false; }
    if word(bytes, 6) == 0 { return false; }
    true
}

/// Render into `out`, reporting the byte count including the terminator.
/// A count past `out.len()` means the caller's buffer is too small.
/// # C: O(address words)
pub(crate) fn render(bytes: &[u8; ADDRESS_BYTES], scope: u32, port: u16, out: &mut [u8]) -> usize {
    let end = if is_ipv4_in_ipv6(bytes) { EMBEDDED_IPV4_WORDS } else { ADDRESS_WORDS };
    let (mut gap, mut gap_len) = (usize::MAX, 1usize);
    let mut index = 0usize;
    while index < end {
        let mut run = 0usize;
        while index < end && word(bytes, index) == 0 { index += 1; run += 1; }
        if run > gap_len { gap = index - run; gap_len = run; }
        index += 1;
    }
    let mut cursor = 0usize;
    if port != 0 { cursor = ipv4::push(out, cursor, &[OPEN_BRACKET]); }
    index = 0;
    while index < end {
        if index == gap {
            cursor = ipv4::push(out, cursor, &[COLON]);
            index += gap_len;
            if index == end { cursor = ipv4::push(out, cursor, &[COLON]); }
            continue;
        }
        if index > 0 { cursor = ipv4::push(out, cursor, &[COLON]); }
        cursor = ipv4::push_hex(out, cursor, word(bytes, index) as u32);
        index += 1;
    }
    if end == EMBEDDED_IPV4_WORDS {
        if cursor == 0 || out.get(cursor - 1).copied() != Some(COLON) { cursor = ipv4::push(out, cursor, &[COLON]); }
        let quad = [bytes[12], bytes[13], bytes[14], bytes[15]];
        cursor = ipv4::format(quad, 0, out, cursor);
    }
    if scope != 0 {
        cursor = ipv4::push(out, cursor, &[PERCENT]);
        cursor = ipv4::push_decimal(out, cursor, scope);
    }
    if port != 0 {
        cursor = ipv4::push(out, cursor, &[CLOSE_BRACKET, COLON]);
        cursor = ipv4::push_decimal(out, cursor, port.swap_bytes() as u32);
    }
    if cursor < out.len() { out[cursor] = 0; }
    cursor + 1
}
