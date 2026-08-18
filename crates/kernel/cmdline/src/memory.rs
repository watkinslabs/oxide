//! `kernelcore=` / `movablecore=` command-line requests.
//!
//! This module owns only the grammar. The PMM resolves the request against
//! the final usable-page count and its own allocation granularity.

use crate::token;

/// One memory-core value. Bytes retain the byte unit until PMM knows its page
/// size; percentages retain the operator's exact requested percentage.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CoreValue { Bytes(u64), Percent(u64), Mirror }

/// The final request for each memory-core parameter on one command line.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryCoreRequest {
    pub kernelcore: Option<CoreValue>,
    pub movablecore: Option<CoreValue>,
}

fn number(s: &[u8]) -> (u64, usize) {
    let (radix, mut i) = if s.len() > 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
        (16u64, 2usize)
    } else if s.len() > 1 && s[0] == b'0' {
        (8u64, 1usize)
    } else {
        (10u64, 0usize)
    };
    let mut value = 0u64;
    let start = i;
    while i < s.len() {
        let digit = match s[i] {
            c @ b'0'..=b'7' => (c - b'0') as u64,
            c @ b'8'..=b'9' if radix == 10 => (c - b'0') as u64,
            c @ b'a'..=b'f' if radix == 16 => (c - b'a' + 10) as u64,
            c @ b'A'..=b'F' if radix == 16 => (c - b'A' + 10) as u64,
            _ => break,
        };
        if digit >= radix { break; }
        value = value.saturating_mul(radix).saturating_add(digit);
        i += 1;
    }
    if i == start { (0, 0) } else { (value, i) }
}

fn parse_value(value: &[u8]) -> CoreValue {
    if value == b"mirror" { return CoreValue::Mirror; }
    let (number, consumed) = number(value);
    if value.get(consumed) == Some(&b'%') { return CoreValue::Percent(number); }
    let shift = match value.get(consumed) {
        Some(b'K') | Some(b'k') => 10,
        Some(b'M') | Some(b'm') => 20,
        Some(b'G') | Some(b'g') => 30,
        Some(b'T') | Some(b't') => 40,
        Some(b'P') | Some(b'p') => 50,
        Some(b'E') | Some(b'e') => 60,
        _ => 0,
    };
    CoreValue::Bytes(number.saturating_mul(1u64 << shift))
}

/// Parse all memory-core parameters. Later occurrences replace earlier ones
/// independently, so an operator can override either side without erasing
/// the other. # C: O(line length)
pub fn memory_core_request(line: &[u8]) -> MemoryCoreRequest {
    let mut out = MemoryCoreRequest::default();
    for token in token::tokens(line) {
        let (key, value) = token::split_token(token);
        let Some(value) = value else { continue };
        match key {
            b"kernelcore" => out.kernelcore = Some(parse_value(value)),
            b"movablecore" => {
                let parsed = parse_value(value);
                out.movablecore = Some(match parsed { CoreValue::Mirror => CoreValue::Bytes(0), _ => parsed });
            }
            _ => {}
        }
    }
    out
}
