//! IPv4 address text: the component scanner, the dotted-quad parser with its
//! shorthand forms, and the formatter with its optional port suffix.

use super::digits::{at, hex_digit};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const DOT: u16 = b'.' as u16;
const COLON: u16 = b':' as u16;
const DIGIT_ZERO: u16 = b'0' as u16;
const DIGIT_NINE: u16 = b'9' as u16;
const LOWER_X: u16 = b'x' as u16;
const UPPER_X: u16 = b'X' as u16;
const DECIMAL_RADIX: u32 = 10;
const OCTAL_RADIX: u32 = 8;
const HEX_RADIX: u32 = 16;
const OCTET_MAX: u32 = 0xff;
const PORT_MAX: u32 = 0xffff;
const FIELDS: usize = 4;
/// Longest dotted quad with a port, plus the terminator.
pub(crate) const TEXT_UNITS: usize = 32;

/// Outcome of one address parse. `terminator` is the index the scan stopped
/// at and is meaningful only where the caller asked for one.
pub(crate) struct Parsed {
    pub status: u32,
    pub bytes: [u8; 4],
    /// Whether the parse reached the point where it stores the address.
    pub stored: bool,
    pub port: u16,
    pub has_port: bool,
    pub terminator: usize,
}

/// One numeric component, honoring the hex and octal prefixes that the
/// strict form rejects. Advances the cursor even when it fails.
/// # C: O(digits consumed)
pub(crate) fn parse_component(text: &[u16], index: &mut usize, strict: bool, value: &mut u32) -> bool {
    let mut radix = DECIMAL_RADIX;
    if at(text, *index) == DOT { *index += 1; return false; }
    if at(text, *index) == DIGIT_ZERO {
        let next = at(text, *index + 1);
        if next == LOWER_X || next == UPPER_X {
            *index += 2;
            if strict { return false; }
            radix = HEX_RADIX;
        } else if (DIGIT_ZERO..=DIGIT_NINE).contains(&next) {
            *index += 1;
            if strict { return false; }
            radix = OCTAL_RADIX;
        }
    }
    let (mut current, mut previous, mut success) = (0u32, 0u32, false);
    while at(text, *index) != 0 {
        let Some(digit) = hex_digit(at(text, *index)) else { break; };
        if digit >= radix { break; }
        current = current.wrapping_mul(radix).wrapping_add(digit);
        success = true;
        if current < previous { return false; }
        previous = current;
        *index += 1;
    }
    if success { *value = current; }
    success
}

/// Dotted-quad parse. Fewer than four components pack the trailing value
/// into the remaining octets; the strict form requires all four.
/// # C: O(text units)
pub(crate) fn string_to_address(text: &[u16], strict: bool, want_terminator: bool, want_port: bool) -> Parsed {
    let mut fields = [0u32; FIELDS];
    let mut index = 0usize;
    let mut count = 0usize;
    let mut out = Parsed { status: STATUS_INVALID_PARAMETER, bytes: [0; 4], stored: false, port: 0, has_port: false, terminator: 0 };
    loop {
        if !parse_component(text, &mut index, strict, &mut fields[count]) { out.terminator = index; return out; }
        count += 1;
        if at(text, index) != DOT { break; }
        if count == FIELDS { out.terminator = index; return out; }
        index += 1;
    }
    if strict && count < FIELDS { out.terminator = index; return out; }
    out.bytes = match count {
        4 => {
            if fields.iter().any(|field| *field > OCTET_MAX) { out.terminator = index; return out; }
            [fields[0] as u8, fields[1] as u8, fields[2] as u8, fields[3] as u8]
        }
        3 => {
            if fields[0] > OCTET_MAX || fields[1] > OCTET_MAX || fields[2] > PORT_MAX { out.terminator = index; return out; }
            [fields[0] as u8, fields[1] as u8, (fields[2] >> 8) as u8, fields[2] as u8]
        }
        2 => {
            if fields[0] > OCTET_MAX || fields[1] > 0x00ff_ffff { out.terminator = index; return out; }
            [fields[0] as u8, (fields[1] >> 16) as u8, (fields[1] >> 8) as u8, fields[1] as u8]
        }
        _ => [(fields[0] >> 24) as u8, (fields[0] >> 16) as u8, (fields[0] >> 8) as u8, fields[0] as u8],
    };
    out.stored = true;
    out.terminator = index;
    if at(text, index) == COLON {
        index += 1;
        let mut port = 0u32;
        if !parse_component(text, &mut index, false, &mut port) { out.terminator = index; return out; }
        if port == 0 || port > PORT_MAX || at(text, index) != 0 { out.terminator = index; return out; }
        if want_port {
            out.port = (port as u16).swap_bytes();
            out.has_port = true;
            if want_terminator { out.terminator = index; }
        }
    }
    if !want_terminator && at(text, index) != 0 { return out; }
    out.status = STATUS_SUCCESS;
    out
}

/// Dotted quad, with `:port` appended when the port is non-zero. The port
/// arrives in network order and prints in host order.
/// # C: O(1)
pub(crate) fn format(bytes: [u8; 4], port: u16, out: &mut [u8], at_index: usize) -> usize {
    let mut cursor = at_index;
    for (position, octet) in bytes.iter().enumerate() {
        if position != 0 { cursor = push(out, cursor, &[DOT as u8]); }
        cursor = push_decimal(out, cursor, *octet as u32);
    }
    if port != 0 {
        cursor = push(out, cursor, &[COLON as u8]);
        cursor = push_decimal(out, cursor, port.swap_bytes() as u32);
    }
    cursor
}

pub(crate) fn push(out: &mut [u8], at_index: usize, bytes: &[u8]) -> usize {
    let mut cursor = at_index;
    for byte in bytes {
        if cursor < out.len() { out[cursor] = *byte; }
        cursor += 1;
    }
    cursor
}

pub(crate) fn push_decimal(out: &mut [u8], at_index: usize, value: u32) -> usize {
    let mut digits = [0u8; 10];
    let mut count = 0usize;
    let mut rest = value;
    loop {
        digits[count] = DIGIT_ZERO as u8 + (rest % DECIMAL_RADIX) as u8;
        count += 1;
        rest /= DECIMAL_RADIX;
        if rest == 0 { break; }
    }
    let mut cursor = at_index;
    while count != 0 { count -= 1; cursor = push(out, cursor, &[digits[count]]); }
    cursor
}

pub(crate) fn push_hex(out: &mut [u8], at_index: usize, value: u32) -> usize {
    let mut digits = [0u8; 8];
    let mut count = 0usize;
    let mut rest = value;
    loop {
        let nibble = (rest % HEX_RADIX) as u8;
        digits[count] = if nibble < 10 { DIGIT_ZERO as u8 + nibble } else { b'a' + nibble - 10 };
        count += 1;
        rest /= HEX_RADIX;
        if rest == 0 { break; }
    }
    let mut cursor = at_index;
    while count != 0 { count -= 1; cursor = push(out, cursor, &[digits[count]]); }
    cursor
}
