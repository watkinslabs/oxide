// The validity predicate a strict-encoding superblock refuses names on.

use super::fold::enc;
use crate::{casefold_eq, casefold_hash, validate, InvalidName};

#[test]
fn well_formed_names_validate() {
    for name in ["", "abc", "école", "가", "q\u{323}\u{301}", "\u{10FFFF}"] {
        assert!(validate(&enc(), name.as_bytes()), "{name:?} should be valid");
    }
}

#[test]
fn malformed_names_are_refused() {
    let bad: &[&[u8]] = &[
        &[0xff],                    // never a UTF-8 lead byte
        &[0x80],                    // lone continuation
        &[0xc3],                    // truncated 2-byte sequence
        &[0xe2, 0x82],              // truncated 3-byte sequence
        &[0xc0, 0xaf],              // overlong `/`
        &[0xe0, 0x80, 0xaf],        // overlong `/`
        &[0xed, 0xa0, 0x80],        // UTF-16 surrogate
        &[0xf4, 0x90, 0x80, 0x80],  // above U+10FFFF
        &[0xf8, 0x88, 0x80, 0x80, 0x80], // 5-byte form
        b"ok\xffbad",               // valid prefix, invalid tail
    ];
    for name in bad {
        assert!(!validate(&enc(), name), "{name:x?} should be refused");
    }
}

#[test]
fn compare_and_hash_report_malformed_names() {
    let e = enc();
    assert_eq!(casefold_eq(&e, b"abc", &[0xff]), Err(InvalidName));
    assert_eq!(casefold_hash(&e, &[0xc0, 0xaf]), Err(InvalidName));
    // A byte-identical pair is answered without consulting the tables, which is
    // what lets a non-strict superblock still find an opaque-named entry.
    assert_eq!(casefold_eq(&e, &[0xff, 0xfe], &[0xff, 0xfe]), Ok(true));
}
