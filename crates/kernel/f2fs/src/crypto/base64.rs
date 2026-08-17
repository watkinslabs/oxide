//! base64url, unpadded: how a ciphertext name is made printable.
//!
//! The URL-safe alphabet is used because a directory entry may not contain a
//! slash, and the standard alphabet's last two characters are `+` and `/`.
//! There is no padding: a name is not a fixed-width record, and `=` would only
//! make it longer.
//!
//! Decoding must be strict about the bits a short final group does not use.
//! Two encodings of the same bytes would give one directory entry two names,
//! either of which would find it — so the unused bits are required to be zero
//! rather than ignored.

/// The URL-safe alphabet.
const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Characters an encoding of `n` bytes takes. # C: O(1)
pub const fn encoded_len(n: usize) -> usize { (n * 4).div_ceil(3) }

/// The value of one character, or `None` if it is not in the alphabet.
/// # C: O(1)
fn value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Encode `src` into `dst`, returning the characters written.
///
/// `dst` must hold [`encoded_len`] bytes; a shorter buffer writes nothing and
/// returns zero.
/// # C: O(len(src))
pub fn encode(src: &[u8], dst: &mut [u8]) -> usize {
    let need = encoded_len(src.len());
    if dst.len() < need { return 0; }
    let mut w = 0usize;
    let mut chunks = src.chunks_exact(3);
    for c in chunks.by_ref() {
        let ac = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        for shift in [18, 12, 6, 0] {
            dst[w] = ALPHABET[((ac >> shift) & 0x3f) as usize];
            w += 1;
        }
    }
    match chunks.remainder() {
        [a, b] => {
            let ac = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            for shift in [18, 12, 6] {
                dst[w] = ALPHABET[((ac >> shift) & 0x3f) as usize];
                w += 1;
            }
        }
        [a] => {
            let ac = u32::from(*a) << 16;
            for shift in [18, 12] {
                dst[w] = ALPHABET[((ac >> shift) & 0x3f) as usize];
                w += 1;
            }
        }
        _ => {}
    }
    w
}

/// Decode `src` into `dst`, returning the bytes written, or `None` for input
/// that is not a canonical unpadded encoding.
///
/// A final group of one character encodes nothing and is refused; a final
/// group whose spare bits are set is refused, because those bytes have another
/// encoding and one entry must not answer to two names.
/// # C: O(len(src))
pub fn decode(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    let mut w = 0usize;
    let mut chunks = src.chunks_exact(4);
    for c in chunks.by_ref() {
        let mut ac = 0u32;
        for &ch in c { ac = (ac << 6) | u32::from(value(ch)?); }
        for shift in [16, 8, 0] {
            *dst.get_mut(w)? = ((ac >> shift) & 0xff) as u8;
            w += 1;
        }
    }
    match chunks.remainder() {
        [] => Some(w),
        [_] => None,
        [a, b] => {
            let v = (u32::from(value(*a)?) << 12) | (u32::from(value(*b)?) << 6);
            if v & 0x3ff != 0 { return None; }
            *dst.get_mut(w)? = (v >> 10) as u8;
            Some(w + 1)
        }
        [a, b, c] => {
            let v = (u32::from(value(*a)?) << 12)
                | (u32::from(value(*b)?) << 6)
                | u32::from(value(*c)?);
            if v & 0x3 != 0 { return None; }
            *dst.get_mut(w)? = (v >> 10) as u8;
            *dst.get_mut(w + 1)? = (v >> 2) as u8;
            Some(w + 2)
        }
        _ => None,
    }
}
