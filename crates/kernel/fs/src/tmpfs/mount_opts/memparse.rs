// The numeric spellings a tmpfs mount-option value may be written in, and the
// mode spelling `mode=` uses.
//
// A value option is parsed as "a number, then whatever is left". The caller
// decides what a non-empty remainder means — `size=` allows exactly one `%`
// there and nothing else, every other numeric key allows nothing at all. That
// split is why this returns the remainder instead of an `Option`: silently
// dropping trailing text is how `size=64mb` became a 64 MiB mount instead of
// the refusal it must be.

use super::limits::MODE_MASK;

/// Binary magnitude suffixes, smallest first. Each step is another 10 bits.
const SUFFIXES: [char; 6] = ['k', 'm', 'g', 't', 'p', 'e'];
/// Bits added per magnitude step.
const SUFFIX_SHIFT: u32 = 10;

const RADIX_HEX: u32 = 16;
const RADIX_OCT: u32 = 8;
const RADIX_DEC: u32 = 10;

const HEX_PREFIX: &str = "0x";
const OCT_PREFIX: &str = "0";

/// Split `s` into the leading run of digits valid in `radix` and the rest.
/// # C: O(len)
fn split_digits(s: &str, radix: u32) -> (&str, &str) {
    let end = s.find(|c: char| !c.is_digit(radix)).unwrap_or(s.len());
    s.split_at(end)
}

/// Parse a leading unsigned number and return it with the unconsumed text.
///
/// The radix follows the written form: `0x` hex, a leading `0` octal, anything
/// else decimal. An empty or entirely non-numeric string yields `0` and the
/// whole input as the remainder, so a caller that requires a number detects it
/// by the remainder being non-empty.
/// # C: O(len)
pub(crate) fn memparse(s: &str) -> (u64, &str) {
    let (radix, digits) = if let Some(rest) = s.strip_prefix(HEX_PREFIX)
        .or_else(|| s.strip_prefix("0X"))
    {
        // A bare `0x` is the number zero followed by an `x`, not a hex number.
        if rest.starts_with(|c: char| c.is_digit(RADIX_HEX)) { (RADIX_HEX, rest) }
        else { (RADIX_DEC, s) }
    } else if s.len() > 1 && s.starts_with(OCT_PREFIX) {
        (RADIX_OCT, s)
    } else {
        (RADIX_DEC, s)
    };
    let (num, rest) = split_digits(digits, radix);
    if num.is_empty() { return (0, s); }
    // A value too large to represent saturates rather than wrapping: wrapping
    // would turn an absurd request into a small, plausible, accepted one.
    let mut val = u64::from_str_radix(num, radix).unwrap_or(u64::MAX);
    let mut rest = rest;
    if let Some(first) = rest.chars().next() {
        let lower = first.to_ascii_lowercase();
        if let Some(idx) = SUFFIXES.iter().position(|&c| c == lower) {
            let shift = SUFFIX_SHIFT * (idx as u32 + 1);
            val = if shift >= u64::BITS { u64::MAX } else { val.checked_shl(shift).unwrap_or(u64::MAX) };
            rest = &rest[first.len_utf8()..];
        }
    }
    (val, rest)
}

/// Parse `mode=` — an OCTAL permission word, masked to the permission and
/// set-id bits. Returns `None` on anything that is not exactly an octal number.
/// # C: O(len)
pub(crate) fn parse_mode(s: &str) -> Option<u16> {
    if s.is_empty() { return None; }
    u32::from_str_radix(s, RADIX_OCT).ok().map(|m| (m & MODE_MASK) as u16)
}

/// Parse a plain unsigned decimal value with no trailing text (`uid=`/`gid=`).
/// # C: O(len)
pub(crate) fn parse_u32(s: &str) -> Option<u32> {
    if s.is_empty() { return None; }
    s.parse::<u32>().ok()
}
