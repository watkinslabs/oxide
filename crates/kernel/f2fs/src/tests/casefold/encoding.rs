// What mounts and what refuses. A volume whose folding rules this build does
// not have must not mount: folding by the only rules it has would answer
// lookups wrongly with no error anywhere, which is worse than not mounting.

use crate::casefold::{
    encoding_for, Casefold, EncodingRefusal, ENC_NO_COMPAT_FALLBACK_FL, ENC_STRICT_MODE_FL,
    F2FS_ENC_UTF8_12_1,
};

use super::fixture::{lenient, no_fallback, strict};

#[test]
fn the_defined_encoding_number_names_utf8_folding_by_unicode_12_1() {
    let info = encoding_for(F2FS_ENC_UTF8_12_1).expect("the one defined encoding");
    assert_eq!(info.magic, 1);
    assert_eq!(info.charset, "utf8");
    assert_eq!(info.major, 12);
    assert_eq!(info.minor, 1);
    assert_eq!(info.revision, 0);
    assert_eq!(info.version().major(), 12);
    assert_eq!(info.version().minor(), 1);
    assert_eq!(info.version().revision(), 0);
}

#[test]
fn an_encoding_number_no_format_defines_is_refused() {
    // Zero is not "no encoding": the feature bit is what says a volume folds,
    // and a folding volume whose number is zero names nothing.
    assert_eq!(encoding_for(0), None);
    assert_eq!(encoding_for(2), None);
    assert_eq!(encoding_for(u16::MAX), None);
    assert_eq!(Casefold::load(0, 0).err(), Some(EncodingRefusal::UnknownEncoding(0)));
    assert_eq!(Casefold::load(2, 0).err(), Some(EncodingRefusal::UnknownEncoding(2)));
    assert_eq!(
        Casefold::load(u16::MAX, 0).err(),
        Some(EncodingRefusal::UnknownEncoding(u16::MAX))
    );
}

#[test]
fn the_defined_encoding_loads_a_table() {
    let cf = Casefold::load(F2FS_ENC_UTF8_12_1, 0).expect("table is compiled in");
    assert_eq!(cf.info().charset, "utf8");
    assert_eq!(cf.flags(), 0);
}

#[test]
fn a_flag_bit_this_build_does_not_understand_is_refused() {
    // Every bit defined so far changes how a name resolves, so an unknown one
    // is assumed to as well.
    assert_eq!(
        Casefold::load(F2FS_ENC_UTF8_12_1, 1 << 15).err(),
        Some(EncodingRefusal::UnknownFlags(1 << 15))
    );
    assert_eq!(
        Casefold::load(F2FS_ENC_UTF8_12_1, ENC_STRICT_MODE_FL | (1 << 2)).err(),
        Some(EncodingRefusal::UnknownFlags(1 << 2))
    );
}

#[test]
fn the_two_defined_flag_bits_are_independent() {
    assert!(!lenient().strict());
    assert!(!lenient().no_compat_fallback());

    assert!(strict().strict());
    assert!(!strict().no_compat_fallback());

    assert!(!no_fallback().strict());
    assert!(no_fallback().no_compat_fallback());

    let both = Casefold::load(
        F2FS_ENC_UTF8_12_1,
        ENC_STRICT_MODE_FL | ENC_NO_COMPAT_FALLBACK_FL,
    )
    .unwrap();
    assert!(both.strict());
    assert!(both.no_compat_fallback());
    assert_eq!(both.flags(), 3);
}

#[test]
fn the_flag_values_are_the_ones_the_format_stores() {
    // Read off the format, not chosen here: bit 0 is strictness, bit 1 is the
    // no-older-entries assertion. Swapping them silently inverts both.
    assert_eq!(ENC_STRICT_MODE_FL, 0x1);
    assert_eq!(ENC_NO_COMPAT_FALLBACK_FL, 0x2);
    assert_eq!(F2FS_ENC_UTF8_12_1, 1);
}
