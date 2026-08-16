// Linux `kstrtoul` / `kstrtol` string→integer conversion for sysfs `store`
// buffers. Sysfs writes arrive as a raw byte buffer that userspace almost
// always terminates with one newline (`echo`), so the contract is: exactly one
// optional trailing newline, no other trailing garbage, an auto-detected radix
// when the caller asks for base 0, `EINVAL` on any malformed input and
// `ERANGE` on overflow.
//
// Module manifest: this crate is one contract and stays a single file — the
// parser plus its radix-fixup helper and the conversion tests.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Failure of a `kstrto*` conversion. Maps 1:1 onto the two errnos Linux
/// returns from these helpers.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// Empty buffer, a character outside the radix, or trailing garbage.
    Inval,
    /// Value does not fit the destination width.
    Range,
}

/// Caller-requested radix; `AUTO` reproduces Linux base 0 prefix detection.
pub const BASE_AUTO: u32 = 0;
const BASE_OCTAL: u32 = 8;
const BASE_DECIMAL: u32 = 10;
const BASE_HEX: u32 = 16;
const HEX_PREFIX_LEN: usize = 2;

/// Drop the single optional trailing newline Linux tolerates. # C: O(1)
fn strip_terminator(buf: &[u8]) -> &[u8] {
    match buf.split_last() {
        Some((b'\n', head)) => head,
        _ => buf,
    }
}

/// Linux `_parse_integer_fixup_radix`: with base 0, `0x`/`0X` before a hex
/// digit selects 16, a bare leading `0` selects 8, anything else 10. # C: O(1)
fn fixup_radix(s: &[u8], base: u32) -> (&[u8], u32) {
    if base != BASE_AUTO { return (s, base); }
    if s.first() != Some(&b'0') { return (s, BASE_DECIMAL); }
    let hex = matches!(s.get(1), Some(b'x' | b'X'))
        && s.get(HEX_PREFIX_LEN).is_some_and(u8::is_ascii_hexdigit);
    if hex { (&s[HEX_PREFIX_LEN..], BASE_HEX) } else { (s, BASE_OCTAL) }
}

/// Digit value of `c` in `base`, or `None` when it is not a digit there.
/// # C: O(1)
fn digit(c: u8, base: u32) -> Option<u32> {
    let value = match c {
        b'0'..=b'9' => u32::from(c - b'0'),
        b'a'..=b'z' => u32::from(c - b'a') + BASE_DECIMAL,
        b'A'..=b'Z' => u32::from(c - b'A') + BASE_DECIMAL,
        _ => return None,
    };
    if value < base { Some(value) } else { None }
}

/// Linux `kstrtoull`: unsigned conversion of a sysfs store buffer. A leading
/// `+` is accepted, a leading `-` is not. # C: O(n)
pub fn kstrtoull(buf: &[u8], base: u32) -> Result<u64, ParseError> {
    let s = strip_terminator(buf);
    let s = s.strip_prefix(b"+").unwrap_or(s);
    let (s, base) = fixup_radix(s, base);
    if s.is_empty() { return Err(ParseError::Inval); }
    let mut acc: u64 = 0;
    for &c in s {
        let d = digit(c, base).ok_or(ParseError::Inval)?;
        acc = acc.checked_mul(u64::from(base)).ok_or(ParseError::Range)?;
        acc = acc.checked_add(u64::from(d)).ok_or(ParseError::Range)?;
    }
    Ok(acc)
}

/// Linux `kstrtoul`. Same width as `kstrtoull` on 64-bit. # C: O(n)
pub fn kstrtoul(buf: &[u8], base: u32) -> Result<u64, ParseError> {
    kstrtoull(buf, base)
}

/// Linux `kstrtoll`: signed conversion. `-` negates the unsigned parse and
/// `ERANGE` covers the magnitude that cannot be represented. # C: O(n)
pub fn kstrtoll(buf: &[u8], base: u32) -> Result<i64, ParseError> {
    let s = strip_terminator(buf);
    let Some(rest) = s.strip_prefix(b"-") else {
        let v = kstrtoull(s, base)?;
        return i64::try_from(v).map_err(|_| ParseError::Range);
    };
    let magnitude = kstrtoull(rest, base)?;
    if magnitude > i64::MIN.unsigned_abs() { return Err(ParseError::Range); }
    Ok((magnitude as i64).wrapping_neg())
}

/// Linux `kstrtol`. # C: O(n)
pub fn kstrtol(buf: &[u8], base: u32) -> Result<i64, ParseError> {
    kstrtoll(buf, base)
}

/// Linux `kstrtoint`: `kstrtol` narrowed to `int`, `ERANGE` when it does not
/// fit. # C: O(n)
pub fn kstrtoint(buf: &[u8], base: u32) -> Result<i32, ParseError> {
    let v = kstrtoll(buf, base)?;
    i32::try_from(v).map_err(|_| ParseError::Range)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_zero_detects_the_radix_from_the_prefix() {
        assert_eq!(kstrtoul(b"10", BASE_AUTO), Ok(10));
        assert_eq!(kstrtoul(b"0x10", BASE_AUTO), Ok(16));
        assert_eq!(kstrtoul(b"0X10", BASE_AUTO), Ok(16));
        assert_eq!(kstrtoul(b"010", BASE_AUTO), Ok(8));
        assert_eq!(kstrtoul(b"0", BASE_AUTO), Ok(0));
        // `0x` with no hex digit after it is octal `0` followed by garbage.
        assert_eq!(kstrtoul(b"0x", BASE_AUTO), Err(ParseError::Inval));
    }

    #[test]
    fn exactly_one_trailing_newline_is_tolerated() {
        assert_eq!(kstrtoul(b"42\n", BASE_AUTO), Ok(42));
        assert_eq!(kstrtoul(b"42\n\n", BASE_AUTO), Err(ParseError::Inval));
        assert_eq!(kstrtoul(b"42 ", BASE_AUTO), Err(ParseError::Inval));
        assert_eq!(kstrtoul(b" 42", BASE_AUTO), Err(ParseError::Inval));
        assert_eq!(kstrtoul(b"", BASE_AUTO), Err(ParseError::Inval));
        assert_eq!(kstrtoul(b"\n", BASE_AUTO), Err(ParseError::Inval));
    }

    #[test]
    fn unsigned_conversion_rejects_a_negative_sign() {
        assert_eq!(kstrtoul(b"-1", BASE_AUTO), Err(ParseError::Inval));
        assert_eq!(kstrtoul(b"+7", BASE_AUTO), Ok(7));
    }

    #[test]
    fn overflow_is_erange_not_a_wrapped_value() {
        assert_eq!(kstrtoul(b"18446744073709551615", BASE_DECIMAL), Ok(u64::MAX));
        assert_eq!(kstrtoul(b"18446744073709551616", BASE_DECIMAL), Err(ParseError::Range));
        assert_eq!(kstrtoint(b"2147483648", BASE_AUTO), Err(ParseError::Range));
        assert_eq!(kstrtoint(b"-2147483648", BASE_AUTO), Ok(i32::MIN));
    }

    #[test]
    fn signed_conversion_covers_both_extremes() {
        assert_eq!(kstrtol(b"-9223372036854775808", BASE_DECIMAL), Ok(i64::MIN));
        assert_eq!(kstrtol(b"-9223372036854775809", BASE_DECIMAL), Err(ParseError::Range));
        assert_eq!(kstrtol(b"9223372036854775807", BASE_DECIMAL), Ok(i64::MAX));
        assert_eq!(kstrtol(b"9223372036854775808", BASE_DECIMAL), Err(ParseError::Range));
    }

    #[test]
    fn explicit_base_rejects_digits_outside_it() {
        assert_eq!(kstrtoul(b"19", BASE_OCTAL), Err(ParseError::Inval));
        assert_eq!(kstrtoul(b"17", BASE_OCTAL), Ok(15));
        assert_eq!(kstrtoul(b"ff", BASE_HEX), Ok(255));
        assert_eq!(kstrtoul(b"FF", BASE_HEX), Ok(255));
        assert_eq!(kstrtoul(b"fg", BASE_HEX), Err(ParseError::Inval));
    }
}
