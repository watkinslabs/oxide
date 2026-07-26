// yescrypt's byte-oriented base64 (salt/hash encoding): same alphabet as
// sha256crypt/sha512crypt ("./0-9A-Za-z"), 3 bytes -> 4 chars LSB-first, with
// support for a non-multiple-of-3 final group (2 bytes -> 3 chars, 1 byte ->
// 2 chars). Distinct from `params::decode64_uint32` (variable-length
// parameter integers) despite sharing the alphabet — see alg-yescrypt-
// common.c's `encode64`/`decode64` vs `encode64_uint32`.
extern crate alloc;
use alloc::vec::Vec;

pub const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// atoi64_partial[c - '.'] for c in '.'..='z' (77 entries); 64 = invalid.
const ATOI64_PARTIAL: [u8; 77] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    64, 64, 64, 64, 64, 64, 64,
    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
    64, 64, 64, 64, 64, 64,
    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
];

/// # C: O(1)
pub fn atoi64(c: u8) -> Option<u8> {
    if !(b'.'..=b'z').contains(&c) { return None; }
    let v = ATOI64_PARTIAL[(c - b'.') as usize];
    if v > 63 { None } else { Some(v) }
}

/// Byte-general crypt-b64 encode: 3 bytes -> 4 chars, LSB-first 6-bit
/// groups; a trailing 1- or 2-byte group emits 2 or 3 chars.
/// # C: O(len(src))
pub fn encode64(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((src.len() * 4 + 2) / 3);
    let mut i = 0;
    while i < src.len() {
        let mut value: u32 = 0;
        let mut bits: u32 = 0;
        while bits < 24 && i < src.len() {
            value |= (src[i] as u32) << bits;
            bits += 8;
            i += 1;
        }
        let mut remaining = bits;
        while remaining > 0 {
            out.push(ITOA64[(value & 0x3f) as usize]);
            value >>= 6;
            remaining = remaining.saturating_sub(6);
        }
    }
    out
}

/// Byte-general crypt-b64 decode, mirroring alg-yescrypt-common.c's
/// `decode64` state machine exactly (including the "leftover encoded bits
/// beyond a whole byte must be zero" padding check). `max_len` bounds the
/// output (salt<=64, hash==32); returns `None` on any malformed input —
/// INCLUDING trailing garbage: an invalid character stops decoding without
/// consuming it (matching decode64's C behavior of returning early rather
/// than erroring), so requiring the whole of `src` to have been consumed
/// (checked below) is what actually rejects it — exactly how yescrypt_r's
/// caller-side `(saltend - saltstr) != saltstrlen` check works.
/// # C: O(len(src))
pub fn decode64(src: &[u8], max_len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while out.len() <= max_len && pos < src.len() {
        let mut value: u32 = 0;
        let mut bits: u32 = 0;
        while pos < src.len() {
            let c = match atoi64(src[pos]) { Some(v) => v, None => break };
            pos += 1;
            value |= (c as u32) << bits;
            bits += 6;
            if bits >= 24 { break; }
        }
        if bits == 0 { break; }
        if bits < 12 { return None; }
        let mut b = bits;
        while out.len() < max_len {
            out.push(value as u8);
            value >>= 8;
            b -= 8;
            if b < 8 {
                if value != 0 { return None; }
                b = 0;
                break;
            }
        }
        if b != 0 { return None; }
    }
    if pos == src.len() && out.len() <= max_len { Some(out) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atoi64_table_matches_itoa64() {
        for (i, &c) in ITOA64.iter().enumerate() { assert_eq!(atoi64(c), Some(i as u8)); }
        assert_eq!(atoi64(b'-'), None);
        assert_eq!(atoi64(b'\0'), None);
    }

    #[test]
    fn roundtrip_various_lengths() {
        for len in [0usize, 1, 2, 3, 4, 5, 6, 16, 32, 64] {
            let src: Vec<u8> = (0..len).map(|i| (i * 37 + 5) as u8).collect();
            let enc = encode64(&src);
            let dec = decode64(&enc, len).unwrap();
            assert_eq!(dec, src, "len={len}");
        }
    }

    #[test]
    fn decode64_rejects_garbage() {
        assert!(decode64(b"!!!!", 4).is_none());
        assert!(decode64(b".", 4).is_none()); // 6 bits, <12, no full byte
    }
}
