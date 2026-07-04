// locale/wchar — multibyte ⇄ wide conversion (docs/59§6 G16). UTF-8 codec
// (the only supported encoding; the C-locale is treated as UTF-8 like glibc's
// C.UTF-8). wchar_t = i32. Pure encode/decode hosted-tested vs Rust core's
// UTF-8; the mb*/wc* C ABI wraps it. Cross-call partial-sequence state is a
// follow-up (callers pass whole characters/buffers).
#![allow(clippy::upper_case_acronyms)]

/// Decode one UTF-8 character from the front of `b`.
/// Ok((codepoint, len)); Err(-1) invalid (EILSEQ); Err(-2) incomplete.
///
/// # C: UTF-8 decode of one scalar value
pub(crate) fn decode_utf8(b: &[u8]) -> Result<(u32, usize), i8> {
    if b.is_empty() { return Err(-2); }
    let b0 = b[0];
    if b0 < 0x80 { return Ok((b0 as u32, 1)); }
    let (len, min, mut cp) = if b0 >= 0xF0 {
        if b0 > 0xF4 { return Err(-1); }
        (4usize, 0x10000u32, (b0 & 0x07) as u32)
    } else if b0 >= 0xE0 {
        (3, 0x800, (b0 & 0x0F) as u32)
    } else if b0 >= 0xC0 {
        (2, 0x80, (b0 & 0x1F) as u32)
    } else {
        return Err(-1); // 0x80..=0xBF: lone continuation
    };
    if b.len() < len { return Err(-2); }
    for &c in &b[1..len] {
        if c & 0xC0 != 0x80 { return Err(-1); }
        cp = (cp << 6) | (c & 0x3F) as u32;
    }
    if cp < min { return Err(-1); } // overlong
    if (0xD800..=0xDFFF).contains(&cp) { return Err(-1); } // surrogate
    if cp > 0x10FFFF { return Err(-1); }
    Ok((cp, len))
}

/// Encode codepoint `cp` to UTF-8; returns (bytes, len). cp must be a valid
/// scalar value (caller-checked).
/// # C: UTF-8 encode of one scalar value
pub(crate) fn encode_utf8(cp: u32) -> ([u8; 4], usize) {
    let mut o = [0u8; 4];
    if cp < 0x80 {
        o[0] = cp as u8;
        (o, 1)
    } else if cp < 0x800 {
        o[0] = 0xC0 | (cp >> 6) as u8;
        o[1] = 0x80 | (cp & 0x3F) as u8;
        (o, 2)
    } else if cp < 0x10000 {
        o[0] = 0xE0 | (cp >> 12) as u8;
        o[1] = 0x80 | ((cp >> 6) & 0x3F) as u8;
        o[2] = 0x80 | (cp & 0x3F) as u8;
        (o, 3)
    } else {
        o[0] = 0xF0 | (cp >> 18) as u8;
        o[1] = 0x80 | ((cp >> 12) & 0x3F) as u8;
        o[2] = 0x80 | ((cp >> 6) & 0x3F) as u8;
        o[3] = 0x80 | (cp & 0x3F) as u8;
        (o, 4)
    }
}

#[cfg(feature = "freestanding")]

// Module manifest: imp owns freestanding C ABI wrappers; tests owns UTF-8 vectors.
#[cfg(feature = "freestanding")]
mod imp;
#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(test)]
mod tests;
