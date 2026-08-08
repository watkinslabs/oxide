// Charset/version parsing and the table-version contract.

use crate::{table_unicode_version, Encoding, EncodingError, UnicodeVersion};

#[test]
fn charset_names_parse() {
    let table = table_unicode_version();
    assert_eq!(UnicodeVersion::parse_charset("utf8", table), Some(table));
    assert_eq!(UnicodeVersion::parse_charset("utf8-12.1.0", table),
               Some(UnicodeVersion::new(12, 1, 0)));
    assert_eq!(UnicodeVersion::parse_charset("UTF8-12.1.0", table),
               Some(UnicodeVersion::new(12, 1, 0)));
    for bad in ["latin1", "utf8-", "utf8-12", "utf8-12.1", "utf8-12.1.0.0",
                "utf8-a.b.c", "utf8-999.1.0", "utf8_12.1.0", "", "utf16-12.1.0"] {
        assert_eq!(UnicodeVersion::parse_charset(bad, table), None, "{bad:?} should not parse");
    }
}

#[test]
fn version_words_round_trip() {
    let v = UnicodeVersion::new(12, 1, 0);
    assert_eq!((v.major(), v.minor(), v.revision()), (12, 1, 0));
    assert_eq!(UnicodeVersion::from_packed(v.packed()), v);
    assert!(UnicodeVersion::new(12, 1, 0) < UnicodeVersion::new(15, 0, 0));
}

#[test]
fn the_table_carries_the_version_it_was_generated_from() {
    let table = table_unicode_version();
    assert!(table >= UnicodeVersion::new(12, 1, 0), "table predates the ext4 default");
    assert_eq!(Encoding::from_charset("utf8").unwrap().version(), table);
    // A filesystem's declared version is what it reports back, not the table's.
    assert_eq!(Encoding::load(UnicodeVersion::new(12, 1, 0)).unwrap().version(),
               UnicodeVersion::new(12, 1, 0));
}

#[test]
fn a_version_newer_than_the_table_is_refused() {
    let newer = UnicodeVersion::new(table_unicode_version().major() + 1, 0, 0);
    assert!(matches!(Encoding::load(newer), Err(EncodingError::UnsupportedVersion)));
    assert!(matches!(Encoding::from_charset("latin1"), Err(EncodingError::UnknownCharset)));
}
