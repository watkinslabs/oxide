//! Digit classification shared by the IP address string services: the hex
//! table the address parsers consult, and the wide unsigned-long conversion
//! the IPv6 component parser is defined in terms of.

const DIGIT_ZERO: u16 = b'0' as u16;
const DIGIT_NINE: u16 = b'9' as u16;
const UPPER_A: u16 = b'A' as u16;
const UPPER_F: u16 = b'F' as u16;
const UPPER_Z: u16 = b'Z' as u16;
const LOWER_A: u16 = b'a' as u16;
const LOWER_F: u16 = b'f' as u16;
const LOWER_Z: u16 = b'z' as u16;
const MINUS: u16 = b'-' as u16;
const PLUS: u16 = b'+' as u16;
const LOWER_X: u16 = b'x' as u16;
const UPPER_X: u16 = b'X' as u16;
const DECIMAL_RADIX: u32 = 10;
const OCTAL_RADIX: u32 = 8;
const HEX_RADIX: u32 = 16;
const MAX_RADIX: u32 = 36;
/// Code units at or above this never index the address parsers' hex table.
const HEX_TABLE_LIMIT: u16 = 0x67;
/// Code points that begin a run of ten decimal digits, ascending.
const DIGIT_ZERO_POINTS: [u16; 17] = [
    0x0660, 0x06f0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0c66, 0x0ce6,
    0x0d66, 0x0e50, 0x0ed0, 0x0f20, 0x1040, 0x17e0, 0x1810, 0xff10,
];

/// Value of one code unit under the address parsers' hex table.
/// # C: O(1)
pub(crate) fn hex_digit(unit: u16) -> Option<u32> {
    if unit >= HEX_TABLE_LIMIT { return None; }
    if (DIGIT_ZERO..=DIGIT_NINE).contains(&unit) { return Some((unit - DIGIT_ZERO) as u32); }
    if (UPPER_A..=UPPER_F).contains(&unit) { return Some((unit - UPPER_A) as u32 + DECIMAL_RADIX); }
    if (LOWER_A..=LOWER_F).contains(&unit) { return Some((unit - LOWER_A) as u32 + DECIMAL_RADIX); }
    None
}

/// Value of one code unit under the wide conversion table, which spans the
/// full alphabet and the decimal digit runs of the non-Latin scripts.
/// # C: O(number of digit runs)
pub(crate) fn wide_digit(unit: u16) -> Option<u32> {
    if (DIGIT_ZERO..=DIGIT_NINE).contains(&unit) { return Some((unit - DIGIT_ZERO) as u32); }
    if (UPPER_A..=UPPER_Z).contains(&unit) { return Some((unit - UPPER_A) as u32 + DECIMAL_RADIX); }
    if (LOWER_A..=LOWER_Z).contains(&unit) { return Some((unit - LOWER_A) as u32 + DECIMAL_RADIX); }
    for zero in DIGIT_ZERO_POINTS {
        if unit < zero { break; }
        if unit <= zero + (DIGIT_NINE - DIGIT_ZERO) { return Some((unit - zero) as u32); }
    }
    None
}

fn is_wide_space(unit: u16) -> bool {
    unit == b' ' as u16 || (0x09..=0x0d).contains(&unit)
}

/// One code unit of a slice, with the implicit terminator past its end.
/// # C: O(1)
pub(crate) fn at(text: &[u16], index: usize) -> u16 { text.get(index).copied().unwrap_or(0) }

/// Wide unsigned-long conversion: saturating value plus the index the
/// conversion stopped at, which stays at the start when no digit converted.
/// # C: O(digits consumed)
pub(crate) fn wcstoul(text: &[u16], start: usize, radix: u32) -> (u32, usize) {
    if radix == 1 || radix > MAX_RADIX { return (0, start); }
    let mut index = start;
    while is_wide_space(at(text, index)) { index += 1; }
    let mut negative = false;
    if at(text, index) == MINUS { negative = true; index += 1; }
    else if at(text, index) == PLUS { index += 1; }
    let prefixed = at(text, index + 1) == LOWER_X || at(text, index + 1) == UPPER_X;
    let mut radix = radix;
    if (radix == 0 || radix == HEX_RADIX) && wide_digit(at(text, index)) == Some(0) && prefixed {
        radix = HEX_RADIX;
        index += 2;
    }
    if radix == 0 { radix = if wide_digit(at(text, index)) != Some(0) { DECIMAL_RADIX } else { OCTAL_RADIX }; }
    let mut value = 0u32;
    let mut empty = true;
    while at(text, index) != 0 {
        let Some(digit) = wide_digit(at(text, index)) else { break; };
        if digit >= radix { break; }
        index += 1;
        empty = false;
        value = if value > u32::MAX / radix || value * radix > u32::MAX - digit { u32::MAX } else { value * radix + digit };
    }
    let end = if empty { start } else { index };
    (if negative { 0u32.wrapping_sub(value) } else { value }, end)
}
