//! The code page: what a byte means, and the byte a character needs.

use crate::name::codepage::{by_number, CP437, CP850, CP852, CP855, CP857, CP860, CP861, CP862, CP863, CP864, CP865, CP866, DEFAULT_CODEPAGE};

/// Below 0x80 a byte is the character of the same value, which is why reading
/// an ASCII name without a code page at all looks correct and is not.
#[test]
fn ascii_maps_to_itself_both_ways() {
    for b in 0u8..0x80 {
        assert_eq!(CP437.to_char(b), u16::from(b), "byte {b:#04x}");
        assert_eq!(CP437.from_char(u16::from(b)), Some(b));
    }
}

/// Above it the byte means something else entirely. These are the mappings a
/// byte-for-character reader gets wrong, and the reason a name written on
/// another machine came back as the wrong word.
#[test]
fn the_high_range_is_not_latin_1() {
    // (byte, character it means on this page)
    const CASES: &[(u8, u16)] = &[
        (0x80, 0x00c7), // capital C with cedilla
        (0x81, 0x00fc), // small u with diaeresis
        (0x9b, 0x00a2), // cent sign
        (0xb0, 0x2591), // light shade
        (0xe1, 0x00df), // small sharp s
        (0xe5, 0x03c3), // small sigma
        (0xff, 0x00a0), // no-break space
    ];
    for (byte, ch) in CASES.iter().copied() {
        assert_eq!(CP437.to_char(byte), ch, "byte {byte:#04x}");
        assert_ne!(ch, u16::from(byte), "and it is NOT the character of the same value");
        assert_eq!(CP437.from_char(ch), Some(byte), "and it comes back");
    }
}

/// The table is injective, so inverting it is exact — a second table for the
/// reverse direction would be a second place for the same fact to be wrong.
#[test]
fn the_table_is_injective() {
    for b in 0u8..=0xff {
        assert_eq!(CP437.from_char(CP437.to_char(b)), Some(b), "byte {b:#04x}");
    }
    for b in 0u8..=0xff {
        assert_eq!(CP852.from_char(CP852.to_char(b)), Some(b), "CP852 byte {b:#04x}");
    }
    for b in 0u8..=0xff {
        assert_eq!(CP855.from_char(CP855.to_char(b)), Some(b), "CP855 byte {b:#04x}");
    }
}

/// A character the page cannot store has no byte. That is not an error: it is
/// what forces a created name to keep its long form.
#[test]
fn a_character_outside_the_page_has_no_byte() {
    assert_eq!(CP437.from_char(0x4e2d), None, "a CJK ideograph");
    assert_eq!(CP437.from_char(0x0100), None, "capital A with macron");
}

/// Case folding is a property of the PAGE, over bytes — a byte whose
/// uppercase the page cannot store stays as it is.
#[test]
fn case_folds_through_the_page_and_stops_where_the_page_does() {
    assert_eq!(CP437.to_upper(b'a'), b'A');
    assert_eq!(CP437.to_lower(b'Z'), b'z');
    assert_eq!(CP437.to_upper(0x81), 0x9a, "u with diaeresis has an uppercase here");
    assert_eq!(CP437.to_lower(0x9a), 0x81);
    assert_eq!(CP437.to_upper(0xe1), 0xe1, "sharp s has no uppercase on this page");
    assert_eq!(CP437.to_upper(0xb0), 0xb0, "and a box-drawing byte has no case at all");
}

/// The mount option names the page by number, and a number this build has no
/// table for is refused rather than silently defaulted.
#[test]
fn a_page_is_found_by_its_number() {
    assert!(by_number(DEFAULT_CODEPAGE).is_some());
    assert_eq!(by_number(DEFAULT_CODEPAGE).map(|p| p.number), Some(437));
    assert_eq!(by_number(850).map(|p| p.number), Some(850));
    assert_eq!(CP850.to_char(0x9b), 0x00f8, "CP850 maps 0x9b to o-slash");
    assert_eq!(CP850.from_char(0x00f8), Some(0x9b));
    assert_eq!(CP850.to_upper(0x81), 0x9a);
    assert_eq!(CP850.to_lower(0x9a), 0x81);
    assert_eq!(by_number(852).map(|p| p.number), Some(852));
    assert_eq!(CP852.to_char(0x86), 0x0107);
    assert_eq!(CP852.to_char(0x8a), 0x0150);
    assert_eq!(CP852.from_char(0x017e), Some(0xa7));
    assert_eq!(CP852.to_lower(0x8d), 0xab);
    assert_eq!(CP852.to_upper(0xab), 0x8d);
    assert_eq!(by_number(855).map(|p| p.number), Some(855));
    assert_eq!(CP855.to_char(0x80), 0x0452);
    assert_eq!(CP855.to_char(0xa0), 0x0430);
    assert_eq!(CP855.from_char(0x0410), Some(0xa1));
    assert_eq!(CP855.to_lower(0x81), 0x80);
    assert_eq!(CP855.to_upper(0x80), 0x81);
    assert_eq!(by_number(857).map(|p| p.number), Some(857));
    assert_eq!(CP857.to_char(0x8d), 0x0131);
    assert_eq!(CP857.to_char(0x98), 0x0130);
    assert_eq!(CP857.from_char(0x011e), Some(0xa6));
    assert_eq!(CP857.to_lower(0xa6), 0xa7);
    assert_eq!(CP857.to_upper(0xa7), 0xa6);
    assert_eq!(by_number(860).map(|p| p.number), Some(860));
    assert_eq!(CP860.to_char(0x8d), 0x00ec);
    assert_eq!(CP860.to_char(0x9e), 0x20a7);
    assert_eq!(CP860.from_char(0x03b1), Some(0xe0));
    assert_eq!(CP860.to_lower(0x80), 0x87);
    assert_eq!(CP860.to_upper(0x87), 0x80);
    assert_eq!(by_number(861).map(|p| p.number), Some(861));
    assert_eq!(CP861.to_char(0x8b), 0x00d0);
    assert_eq!(CP861.to_char(0x9e), 0x20a7);
    assert_eq!(CP861.from_char(0x03b1), Some(0xe0));
    assert_eq!(CP861.to_lower(0x8b), 0x8c);
    assert_eq!(by_number(862).map(|p| p.number), Some(862));
    assert_eq!(CP862.to_char(0x80), 0x05d0);
    assert_eq!(CP862.to_char(0x9a), 0x05ea);
    assert_eq!(CP862.from_char(0x05d0), Some(0x80));
    assert_eq!(by_number(863).map(|p| p.number), Some(863));
    assert_eq!(CP863.to_char(0x80), 0x00c7);
    assert_eq!(CP863.to_char(0x86), 0x00b6);
    assert_eq!(CP863.from_char(0x2017), Some(0x8d));
    assert_eq!(by_number(864).map(|p| p.number), Some(864));
    assert_eq!(CP864.to_char(0x80), 0x00b0);
    assert_eq!(CP864.to_char(0xb0), 0x0660);
    assert_eq!(CP864.from_char(0x060c), Some(0xac));
    assert_eq!(by_number(865).map(|p| p.number), Some(865));
    assert_eq!(CP865.to_char(0x80), 0x00c7);
    assert_eq!(CP865.to_char(0x9f), 0x0192);
    assert_eq!(CP865.from_char(0x20a7), Some(0x9e));
    assert_eq!(CP865.to_lower(0x80), 0x87);
    assert_eq!(CP865.to_upper(0x87), 0x80);
    assert_eq!(by_number(866).map(|p| p.number), Some(866));
    assert_eq!(CP866.to_char(0x80), 0x0410);
    assert_eq!(CP866.to_char(0xb0), 0x2591);
    assert_eq!(CP866.from_char(0x0451), Some(0xf1));
    assert_eq!(CP866.to_lower(0x80), 0xa0);
    assert_eq!(CP866.to_upper(0xa0), 0x80);
}
