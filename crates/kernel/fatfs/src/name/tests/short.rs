//! Reading the 8.3 name: padding, the dot, the escape, the code page and the
//! three display rules.

use crate::name::codepage::CP437;
use crate::name::flags::{CASE_LOWER_BASE, CASE_LOWER_EXT, SFN_DEFAULT, SFN_DISPLAY_LOWER,
                         SFN_DISPLAY_WIN95, SFN_DISPLAY_WINNT};
use crate::name::short::decode;

use alloc::string::String;

fn name(raw: &[u8; 11], lcase: u8, opts: u16) -> String { decode(raw, lcase, &CP437, opts) }

#[test]
fn padding_goes_and_the_dot_arrives_only_with_an_extension() {
    assert_eq!(name(b"README  TXT", 0, SFN_DEFAULT), "README.TXT");
    assert_eq!(name(b"MAKEFILE   ", 0, SFN_DEFAULT), "MAKEFILE");
    assert_eq!(name(b"A       B  ", 0, SFN_DEFAULT), "A.B");
    assert_eq!(name(b"           ", 0, SFN_DEFAULT), "", "eleven spaces name nothing");
}

/// The escape is only ever the FIRST byte, and it stands for the value that
/// would otherwise mark the slot free.
#[test]
fn the_escaped_first_byte_becomes_the_value_it_stands_for() {
    let mut raw = *b"?ILE    TXT";
    raw[0] = 0x05;
    // 0xE5 is a small sigma on this page, which is the point: the escape
    // restores the BYTE, and the code page then says what that byte means.
    assert_eq!(name(&raw, 0, SFN_DEFAULT), "\u{3c3}ILE.TXT");
    let mut mid = *b"FILE?   TXT";
    mid[4] = 0x05;
    assert_eq!(name(&mid, 0, SFN_DEFAULT), "FILE\u{5}.TXT",
               "and a 0x05 anywhere else is not an escape");
}

/// The whole reason a code page is needed: the same eleven bytes are two
/// different names under two different pages, and the one this reads under is
/// the mount's.
#[test]
fn high_bytes_read_through_the_code_page() {
    assert_eq!(name(b"\x81BER    TXT", 0, SFN_DEFAULT), "\u{fc}BER.TXT");
    assert_ne!(name(b"\x81BER    TXT", 0, SFN_DEFAULT), "\u{81}BER.TXT",
               "not the character of the same value");
}

/// The three display rules differ only on a name whose case bits are set, and
/// that is the only place the difference is visible.
#[test]
fn the_display_rule_decides_what_the_case_bits_do() {
    let raw = b"README  TXT";
    let both = CASE_LOWER_BASE | CASE_LOWER_EXT;
    assert_eq!(name(raw, both, SFN_DISPLAY_WINNT), "readme.txt",
               "winnt honours what the entry recorded");
    assert_eq!(name(raw, both, SFN_DISPLAY_WIN95), "README.TXT",
               "win95 ignores the bits entirely");
    assert_eq!(name(raw, 0, SFN_DISPLAY_LOWER), "readme.txt",
               "lower folds whatever the bits say");
    assert_eq!(name(raw, CASE_LOWER_BASE, SFN_DISPLAY_WINNT), "readme.TXT",
               "the two halves are recorded separately");
    assert_eq!(name(raw, CASE_LOWER_EXT, SFN_DISPLAY_WINNT), "README.txt");
}

/// Folding is over the BYTES of the code page, so it reaches characters the
/// ASCII rule does not.
#[test]
fn folding_reaches_the_high_range_the_page_has_case_for() {
    // 0x9a is capital U with diaeresis; its lowercase on this page is 0x81.
    assert_eq!(name(b"\x9aBER    TXT", CASE_LOWER_BASE, SFN_DISPLAY_WINNT), "\u{fc}ber.TXT");
    assert_eq!(name(b"\x9aBER    TXT", 0, SFN_DISPLAY_WINNT), "\u{dc}BER.TXT",
               "and unfolded it is the capital the page stores at that byte");
    // A box-drawing byte has no case, so the rule leaves it alone.
    assert_eq!(name(b"\xb0          ", 0, SFN_DISPLAY_LOWER), "\u{2591}");
}

/// A NUL ends the field. A record another system left half-written must not
/// produce a name holding NUL characters, which no path can hold.
#[test]
fn a_nul_ends_the_field_it_is_in() {
    assert_eq!(name(b"AB\0DEFGHTXT", 0, SFN_DEFAULT), "AB.TXT");
    assert_eq!(name(b"ABCDEFGHT\0T", 0, SFN_DEFAULT), "ABCDEFGH.T");
}
