//! The one conversion between the Win32 wide string every kernel-side record
//! keeps and the byte string an ANSI entry point hands its caller. The native
//! ANSI code page of this personality encodes every code point as UTF-8, so
//! one character can occupy up to four bytes and a length in characters is
//! never a length in bytes.
//!
//! A lone surrogate carries no pair to complete it and still has to survive
//! the round trip a caller may perform, so it encodes as its own scalar value
//! rather than being replaced or dropped.
use alloc::vec::Vec;

/// First and last unit of the high half of a surrogate pair.
const HIGH_SURROGATE_FIRST: u16 = 0xd800;
const HIGH_SURROGATE_LAST: u16 = 0xdbff;
/// First and last unit of the low half of a surrogate pair.
const LOW_SURROGATE_FIRST: u16 = 0xdc00;
const LOW_SURROGATE_LAST: u16 = 0xdfff;
/// What a completed surrogate pair adds to its assembled ten-bit halves.
const SUPPLEMENTARY_BASE: u32 = 0x1_0000;
const SURROGATE_HALF_BITS: u32 = 10;

/// Largest scalar each encoded length can carry.
const ONE_BYTE_MAX: u32 = 0x7f;
const TWO_BYTE_MAX: u32 = 0x7ff;
const THREE_BYTE_MAX: u32 = 0xffff;
/// Lead-byte tags and the continuation-byte tag with its payload mask.
const TWO_BYTE_LEAD: u8 = 0xc0;
const THREE_BYTE_LEAD: u8 = 0xe0;
const FOUR_BYTE_LEAD: u8 = 0xf0;
const CONTINUATION_LEAD: u8 = 0x80;
const CONTINUATION_MASK: u32 = 0x3f;
const CONTINUATION_BITS: u32 = 6;

/// Encode one scalar value into the native ANSI code page.
/// # C: O(1)
pub fn push_ansi(output: &mut Vec<u8>, value: u32) {
    let tail = |shift: u32| CONTINUATION_LEAD | ((value >> shift) & CONTINUATION_MASK) as u8;
    if value <= ONE_BYTE_MAX { output.push(value as u8); }
    else if value <= TWO_BYTE_MAX { output.extend_from_slice(&[TWO_BYTE_LEAD | (value >> CONTINUATION_BITS) as u8, tail(0)]); }
    else if value <= THREE_BYTE_MAX { output.extend_from_slice(&[THREE_BYTE_LEAD | (value >> (CONTINUATION_BITS * 2)) as u8, tail(CONTINUATION_BITS), tail(0)]); }
    else { output.extend_from_slice(&[FOUR_BYTE_LEAD | (value >> (CONTINUATION_BITS * 3)) as u8, tail(CONTINUATION_BITS * 2), tail(CONTINUATION_BITS), tail(0)]); }
}

/// Convert a wide string into the native ANSI code page, joining every
/// complete surrogate pair into the one scalar it names.
/// # C: O(units)
pub fn utf16_to_ansi(units: &[u16]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut index = 0usize;
    while index < units.len() {
        let unit = units[index];
        let mut value = unit as u32;
        if (HIGH_SURROGATE_FIRST..=HIGH_SURROGATE_LAST).contains(&unit) && index + 1 < units.len() {
            let next = units[index + 1];
            if (LOW_SURROGATE_FIRST..=LOW_SURROGATE_LAST).contains(&next) {
                value = SUPPLEMENTARY_BASE + (((unit - HIGH_SURROGATE_FIRST) as u32) << SURROGATE_HALF_BITS) + (next - LOW_SURROGATE_FIRST) as u32;
                index += 1;
            }
        }
        push_ansi(&mut output, value);
        index += 1;
    }
    output
}

#[cfg(test)]
#[path = "win32_text/tests.rs"]
mod tests;
