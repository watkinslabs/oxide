//! Strict UTF-8 decoding.
//!
//! Names reach a filesystem as bytes, not as validated strings, so "is this
//! name well formed for the encoding" is a real question a casefolded
//! filesystem with strict encoding must answer. Rejected here: truncated
//! sequences, bad continuation bytes, overlong encodings, surrogates, and
//! anything above `U+10FFFF` — the same set a shortest-form decoder rejects.

use crate::api::InvalidName;

const CONT_MASK: u8 = 0b1100_0000;
const CONT_TAG:  u8 = 0b1000_0000;
const CONT_BITS: u32 = 6;
const CONT_VAL:  u8 = 0b0011_1111;

const LEAD2_TAG: u8 = 0b1100_0000;
const LEAD3_TAG: u8 = 0b1110_0000;
const LEAD4_TAG: u8 = 0b1111_0000;
const LEAD5_TAG: u8 = 0b1111_1000;

const MIN2: u32 = 0x80;
const MIN3: u32 = 0x800;
const MIN4: u32 = 0x1_0000;
const MAX_CODEPOINT: u32 = 0x10_FFFF;
const SURROGATE_FIRST: u32 = 0xD800;
const SURROGATE_LAST: u32 = 0xDFFF;

/// Bytes the UTF-8 encoding of `cp` occupies. # C: O(1)
pub(crate) fn encoded_len(cp: u32) -> usize {
    if cp < MIN2 { 1 } else if cp < MIN3 { 2 } else if cp < MIN4 { 3 } else { 4 }
}

/// Decode the sequence at the front of `s`, returning the codepoint and the
/// bytes it occupied. # C: O(1)
pub(crate) fn decode(s: &[u8]) -> Result<(u32, usize), InvalidName> {
    let b0 = *s.first().ok_or(InvalidName)?;
    let (len, min, mut cp) = if b0 < CONT_TAG {
        return Ok((b0 as u32, 1));
    } else if b0 & LEAD3_TAG == LEAD2_TAG {
        (2usize, MIN2, (b0 & !LEAD3_TAG) as u32)
    } else if b0 & LEAD4_TAG == LEAD3_TAG {
        (3usize, MIN3, (b0 & !LEAD4_TAG) as u32)
    } else if b0 & LEAD5_TAG == LEAD4_TAG {
        (4usize, MIN4, (b0 & !LEAD5_TAG) as u32)
    } else {
        return Err(InvalidName); // continuation byte or 5/6-byte lead
    };
    if s.len() < len { return Err(InvalidName); }
    for &b in &s[1..len] {
        if b & CONT_MASK != CONT_TAG { return Err(InvalidName); }
        cp = (cp << CONT_BITS) | (b & CONT_VAL) as u32;
    }
    if cp < min || cp > MAX_CODEPOINT { return Err(InvalidName); }
    if (SURROGATE_FIRST..=SURROGATE_LAST).contains(&cp) { return Err(InvalidName); }
    Ok((cp, len))
}

/// Encode `cp` into `dst`, returning the bytes written, or `None` if `dst` is
/// too small. # C: O(1)
pub(crate) fn encode(cp: u32, dst: &mut [u8]) -> Option<usize> {
    let len = encoded_len(cp);
    if dst.len() < len { return None; }
    match len {
        1 => dst[0] = cp as u8,
        2 => {
            dst[0] = LEAD2_TAG | (cp >> CONT_BITS) as u8;
            dst[1] = CONT_TAG | (cp as u8 & CONT_VAL);
        }
        3 => {
            dst[0] = LEAD3_TAG | (cp >> (2 * CONT_BITS)) as u8;
            dst[1] = CONT_TAG | ((cp >> CONT_BITS) as u8 & CONT_VAL);
            dst[2] = CONT_TAG | (cp as u8 & CONT_VAL);
        }
        _ => {
            dst[0] = LEAD4_TAG | (cp >> (3 * CONT_BITS)) as u8;
            dst[1] = CONT_TAG | ((cp >> (2 * CONT_BITS)) as u8 & CONT_VAL);
            dst[2] = CONT_TAG | ((cp >> CONT_BITS) as u8 & CONT_VAL);
            dst[3] = CONT_TAG | (cp as u8 & CONT_VAL);
        }
    }
    Some(len)
}
