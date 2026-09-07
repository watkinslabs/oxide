//! IPv6 address text parsing: colon-separated groups, the single zero-run
//! elision, an embedded dotted quad, and the extended scope and port forms.

use super::digits::{at, hex_digit, wcstoul};
use super::ipv4;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const COLON: u16 = b':' as u16;
const DOT: u16 = b'.' as u16;
const PERCENT: u16 = b'%' as u16;
const OPEN_BRACKET: u16 = b'[' as u16;
const CLOSE_BRACKET: u16 = b']' as u16;
const DIGIT_ZERO: u16 = b'0' as u16;
const LOWER_X: u16 = b'x' as u16;
const UPPER_X: u16 = b'X' as u16;
const DECIMAL_RADIX: u32 = 10;
const HEX_RADIX: u32 = 16;
const COMPONENT_MAX: u32 = 0x7fff_ffff;
const ADDRESS_BYTES: usize = 16;
const OCTET_MAX: u32 = 0xff;
const PORT_MAX: u32 = 0xffff;
/// Longest textual address with brackets, scope and port, plus terminator.
pub(crate) const TEXT_UNITS: usize = 128;

pub(crate) struct Parsed {
    pub status: u32,
    pub bytes: [u8; ADDRESS_BYTES],
    /// Whether the parse stored anything into the address it built.
    pub stored: bool,
    pub scope: u32,
    pub port: u16,
    pub terminator: usize,
    pub has_terminator: bool,
}

/// One group, defined by the wide unsigned-long conversion and clamped to
/// the reference's component ceiling.
/// # C: O(digits consumed)
fn parse_component(text: &[u16], index: &mut usize, radix: u32, value: &mut u32) -> bool {
    if hex_digit(at(text, *index)).is_none() { return false; }
    let (converted, mut end) = wcstoul(text, *index, radix);
    *value = converted.min(COMPONENT_MAX);
    if at(text, end) == DIGIT_ZERO { end += 1; } else if end == *index { return false; }
    *index = end;
    true
}

struct Scan { bytes: [u8; ADDRESS_BYTES], stored: bool, n_bytes: usize, gap: Option<usize> }

impl Scan {
    fn store_byte(&mut self, value: u32) {
        if self.n_bytes >= ADDRESS_BYTES { return; }
        self.bytes[self.n_bytes] = value as u8;
        self.stored = true;
    }
    fn store_word(&mut self, value: u32) {
        let slot = self.n_bytes / 2 * 2;
        if slot + 2 > ADDRESS_BYTES { return; }
        self.bytes[slot..slot + 2].copy_from_slice(&(value as u16).to_be_bytes());
        self.stored = true;
    }
}

/// Full parse. `ex` admits the bracketed, scoped and ported forms; the plain
/// form reports the index it stopped at instead.
/// # C: O(text units)
pub(crate) fn string_to_address(text: &[u16], ex: bool, want_terminator: bool) -> Parsed {
    let mut scan = Scan { bytes: [0; ADDRESS_BYTES], stored: false, n_bytes: 0, gap: None };
    let mut out = Parsed { status: STATUS_INVALID_PARAMETER, bytes: scan.bytes, stored: false, scope: 0, port: 0, terminator: 0, has_terminator: false };
    let mut index = 0usize;
    let mut expecting_port = false;
    let (mut has_prefixed, mut too_big, mut n_ipv4_bytes) = (false, false, 0usize);
    let mut component = 0u32;
    if at(text, index) == OPEN_BRACKET {
        if !ex { return fail(out, scan, index, want_terminator); }
        expecting_port = true;
        index += 1;
    }
    if at(text, index) == COLON {
        if at(text, index + 1) != COLON { return fail(out, scan, index, want_terminator); }
        index += 1;
        scan.store_word(0);
    }
    let mut filled = false;
    loop {
        let mut previous = index;
        if n_ipv4_bytes == 0 && at(text, index) == COLON {
            if scan.gap.is_some() { return fail(out, scan, index, want_terminator); }
            index += 1;
            previous = index;
            scan.gap = Some(scan.n_bytes);
            if scan.n_bytes == 14 || !parse_component(text, &mut index, HEX_RADIX, &mut component) { break; }
            index = previous;
        }
        if n_ipv4_bytes == 0 && scan.n_bytes <= if scan.gap.is_some() { 10 } else { 12 } {
            let mut probe = index;
            if parse_component(text, &mut probe, DECIMAL_RADIX, &mut component) && at(text, probe) == DOT { n_ipv4_bytes = 1; }
        }
        if n_ipv4_bytes != 0 {
            if !parse_component(text, &mut index, DECIMAL_RADIX, &mut component) { return fail(out, scan, index, want_terminator); }
            if index - previous > 3 || component > OCTET_MAX { too_big = true; }
            else {
                if at(text, index) != DOT && (n_ipv4_bytes < 4 || (scan.n_bytes < 15 && scan.gap.is_none())) { return fail(out, scan, index, want_terminator); }
                scan.store_byte(component);
                scan.n_bytes += 1;
            }
            if n_ipv4_bytes == 4 || at(text, index) != DOT { break; }
            n_ipv4_bytes += 1;
        } else {
            if !parse_component(text, &mut index, HEX_RADIX, &mut component) { return fail(out, scan, index, want_terminator); }
            if at(text, previous) == DIGIT_ZERO && (at(text, previous + 1) == LOWER_X || at(text, previous + 1) == UPPER_X) {
                // The trailing group may carry a hex prefix and overrun four
                // digits; the reference reports the prefix letter as the stop.
                out.terminator = previous + 1;
                out.has_terminator = want_terminator;
                if scan.n_bytes < 14 && scan.gap.is_none() { out.bytes = scan.bytes; out.stored = scan.stored; return out; }
                scan.store_word(component);
                scan.n_bytes += 2;
                has_prefixed = true;
                filled = true;
                break;
            }
            if at(text, index) != COLON && scan.n_bytes < 14 && scan.gap.is_none() { return fail(out, scan, index, want_terminator); }
            if index - previous > 4 { too_big = true; } else { scan.store_word(component); }
            scan.n_bytes += 2;
            if at(text, index) != COLON || (scan.gap.is_some() && at(text, index + 1) == COLON) { break; }
        }
        if scan.n_bytes == if scan.gap.is_some() { 14 } else { 16 } { break; }
        if too_big { out.bytes = scan.bytes; out.stored = scan.stored; return out; }
        index += 1;
    }
    if !filled {
        out.terminator = index;
        out.has_terminator = want_terminator;
        if too_big { out.bytes = scan.bytes; out.stored = scan.stored; return out; }
    }
    match scan.gap {
        None => if scan.n_bytes < ADDRESS_BYTES { return fail(out, scan, index, want_terminator); },
        Some(gap) => {
            let tail = scan.n_bytes - gap;
            scan.bytes.copy_within(gap..scan.n_bytes, ADDRESS_BYTES - tail);
            for slot in &mut scan.bytes[gap..ADDRESS_BYTES - tail] { *slot = 0; }
            scan.stored = true;
        }
    }
    if ex {
        if has_prefixed { return fail(out, scan, index, want_terminator); }
        if at(text, index) == PERCENT {
            index += 1;
            if !ipv4::parse_component(text, &mut index, true, &mut out.scope) { out.scope = 0; return fail(out, scan, index, want_terminator); }
        }
        if expecting_port {
            if at(text, index) != CLOSE_BRACKET { return fail(out, scan, index, want_terminator); }
            index += 1;
            if at(text, index) == COLON {
                index += 1;
                let mut port = 0u32;
                if !ipv4::parse_component(text, &mut index, false, &mut port) { return fail(out, scan, index, want_terminator); }
                if port == 0 || port > PORT_MAX || at(text, index) != 0 { return fail(out, scan, index, want_terminator); }
                out.port = (port as u16).swap_bytes();
            }
        }
    }
    out.bytes = scan.bytes;
    out.stored = scan.stored;
    if !want_terminator && at(text, index) != 0 { return out; }
    out.status = STATUS_SUCCESS;
    out
}

fn fail(mut out: Parsed, scan: Scan, index: usize, want_terminator: bool) -> Parsed {
    out.status = STATUS_INVALID_PARAMETER;
    out.bytes = scan.bytes;
    out.stored = scan.stored;
    out.terminator = index;
    out.has_terminator = want_terminator;
    out
}
