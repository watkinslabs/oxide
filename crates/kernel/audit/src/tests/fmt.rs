use alloc::vec::Vec;

use super::*;

fn s(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> { let mut v = Vec::new(); f(&mut v); v }

#[test]
fn decimal_covers_zero_and_the_widest_value() {
    assert_eq!(s(|o| dec(o, 0)), b"0");
    assert_eq!(s(|o| dec(o, 1)), b"1");
    assert_eq!(s(|o| dec(o, 4_294_967_295)), b"4294967295");
    assert_eq!(s(|o| dec(o, u64::MAX)), b"18446744073709551615");
}

#[test]
fn signed_decimal_keeps_the_most_negative_value() {
    assert_eq!(s(|o| dec_signed(o, -1)), b"-1");
    assert_eq!(s(|o| dec_signed(o, 0)), b"0");
    assert_eq!(s(|o| dec_signed(o, i64::MIN)), b"-9223372036854775808");
}

/// The millisecond field of a record stamp is fixed-width: an unpadded 7 would
/// read as 700 ms.
#[test]
fn padded_decimal_is_fixed_width_but_never_truncates() {
    assert_eq!(s(|o| dec_pad(o, 7, 3)), b"007");
    assert_eq!(s(|o| dec_pad(o, 70, 3)), b"070");
    assert_eq!(s(|o| dec_pad(o, 999, 3)), b"999");
    assert_eq!(s(|o| dec_pad(o, 1234, 3)), b"1234");
}

#[test]
fn hex_has_no_leading_zeros_in_either_case() {
    assert_eq!(s(|o| hex(o, 0)), b"0");
    assert_eq!(s(|o| hex(o, 0xdead_beef)), b"deadbeef");
    assert_eq!(s(|o| hex_upper(o, 0xdead_beef)), b"DEADBEEF");
    assert_eq!(s(|o| hex_upper(o, 0x2a)), b"2A");
}

/// A record is parsed by splitting on unquoted whitespace, so a value with a
/// space, a quote, a control byte or a high byte must not be emitted quoted.
#[test]
fn only_plainly_printable_values_are_quoted() {
    assert!(!needs_hex(b"bash"));
    assert!(needs_hex(b"two words"));
    assert!(needs_hex(b"say\"what"));
    assert!(needs_hex(b"tab\there"));
    assert!(needs_hex(&[0x80]));
    assert!(needs_hex(&[0x7f]));
    assert!(!needs_hex(b"!~"));
}

#[test]
fn untrusted_values_encode_as_quoted_or_hex() {
    assert_eq!(s(|o| untrusted(o, b"bash")), b"\"bash\"");
    assert_eq!(s(|o| untrusted(o, b"a b")), b"612062");
    assert_eq!(s(|o| untrusted(o, b"")), b"(null)");
}
