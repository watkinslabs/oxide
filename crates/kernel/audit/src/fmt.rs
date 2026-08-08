// Record text formatting. An audit record is a flat `key=value` line in a
// byte buffer; `no_std` has no formatter that can be used from an allocation
// context this cold, so the primitives are here and every record body is built
// from them.

extern crate alloc;

use alloc::vec::Vec;

/// Append a decimal unsigned value. # C: O(digits)
pub fn dec(out: &mut Vec<u8>, mut v: u64) {
    if v == 0 { out.push(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut n = 0;
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    while n > 0 { n -= 1; out.push(buf[n]); }
}

/// Append a decimal signed value. # C: O(digits)
pub fn dec_signed(out: &mut Vec<u8>, v: i64) {
    if v < 0 { out.push(b'-'); dec(out, v.unsigned_abs()); } else { dec(out, v as u64); }
}

/// Append a decimal value zero-padded to `width`. # C: O(width)
pub fn dec_pad(out: &mut Vec<u8>, v: u64, width: usize) {
    let mut tmp = Vec::new();
    dec(&mut tmp, v);
    for _ in tmp.len()..width { out.push(b'0'); }
    out.extend_from_slice(&tmp);
}

/// Append lower-case hexadecimal with no leading zeros. # C: O(digits)
pub fn hex(out: &mut Vec<u8>, v: u64) {
    if v == 0 { out.push(b'0'); return; }
    let mut buf = [0u8; 16];
    let mut n = 0;
    let mut v = v;
    while v > 0 { buf[n] = HEX_LOWER[(v & 0xF) as usize]; v >>= 4; n += 1; }
    while n > 0 { n -= 1; out.push(buf[n]); }
}

/// Append upper-case hexadecimal with no leading zeros. # C: O(digits)
pub fn hex_upper(out: &mut Vec<u8>, v: u64) {
    if v == 0 { out.push(b'0'); return; }
    let mut buf = [0u8; 16];
    let mut n = 0;
    let mut v = v;
    while v > 0 { buf[n] = HEX_UPPER[(v & 0xF) as usize]; v >>= 4; n += 1; }
    while n > 0 { n -= 1; out.push(buf[n]); }
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Whether a byte string must be hex-escaped rather than quoted.
///
/// A record is parsed by splitting on unquoted whitespace, so any byte that
/// could end a field early — a quote, anything below the first printable
/// character, anything above the last — forces the whole value into hex. The
/// consumer distinguishes the two encodings by the leading quote.
/// # C: O(len)
pub fn needs_hex(s: &[u8]) -> bool {
    const FIRST_PRINTABLE: u8 = 0x21;
    const LAST_PRINTABLE:  u8 = 0x7e;
    s.iter().any(|c| *c == b'"' || *c < FIRST_PRINTABLE || *c > LAST_PRINTABLE)
}

/// Append a value that came from userspace: quoted when every byte is safely
/// printable, otherwise the byte-for-byte hex encoding.
/// # C: O(len)
pub fn untrusted(out: &mut Vec<u8>, s: &[u8]) {
    if s.is_empty() { out.extend_from_slice(b"(null)"); return; }
    if needs_hex(s) {
        for c in s { out.push(HEX_UPPER[(c >> 4) as usize]); out.push(HEX_UPPER[(c & 0xF) as usize]); }
        return;
    }
    out.push(b'"');
    out.extend_from_slice(s);
    out.push(b'"');
}

#[cfg(test)]
#[path = "tests/fmt.rs"]
mod tests;
