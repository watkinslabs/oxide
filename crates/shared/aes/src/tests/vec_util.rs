// Shared helpers for the AES known-answer tests.

use alloc::vec::Vec;

/// Decode an even-length lowercase/uppercase hex string.
pub(crate) fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex literal must have even length");
    let b = s.as_bytes();
    let mut v = Vec::with_capacity(s.len() / 2);
    let nib = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit"),
        }
    };
    for i in (0..b.len()).step_by(2) { v.push((nib(b[i]) << 4) | nib(b[i + 1])); }
    v
}

/// Render bytes as lowercase hex, for assertion messages.
pub(crate) fn tohex(b: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(b.len() * 2);
    for x in b { let _ = write!(s, "{:02x}", x); }
    s
}

/// Assert `got` equals the hex literal `want`, reporting both as hex.
pub(crate) fn assert_hex(got: &[u8], want: &str) {
    assert_eq!(tohex(got), want, "byte mismatch");
}
