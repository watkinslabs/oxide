use super::*;
use syscall::nt_native_gdi as abi;

#[test]
fn script_string_flags_survive_without_inventing_a_clip_rect() {
    let request = validate(abi::GLYPH_INDEX | abi::IGNORE_LANGUAGE | abi::PDY, 0, 0x2000, 3, 0x3000, 0).unwrap();
    assert_eq!(request.rect, None);
    assert_eq!(request.advances, Some(0x3000));
    assert_eq!(request.count, 3);
}

#[test]
fn paired_advances_require_two_dwords_per_input_unit() {
    let request = validate(abi::PDY, 0, 0x2000, 2, 0, 0).unwrap();
    assert_eq!(request.advances, None);
    let request = validate(abi::PDY, 0, 0x2000, 2, 0x3000, 0).unwrap();
    assert_eq!(request.advances, Some(0x3000));
}

#[test]
fn opaque_and_clipped_flags_are_removed_when_rect_is_null() {
    let request = validate(abi::OPAQUE | abi::CLIPPED | abi::GLYPH_INDEX, 0, 0x2000, 1, 0, 0).unwrap();
    assert_eq!(request.rect, None);
    assert_eq!(request.flags, abi::GLYPH_INDEX);
    assert_eq!(validate(abi::CLIPPED, u64::MAX - 8, 0x2000, 1, 0, 0).unwrap_err(), Error::MissingRect);
    assert!(validate(abi::OPAQUE, 0x4000, 0x2000, 1, 0, 0).is_ok());
}

#[test]
fn glyph_output_rejects_unknown_flags_code_pages_and_pointer_overflow() {
    assert_eq!(validate(0x8000, 0, 0x2000, 1, 0, 0).unwrap_err(), Error::InvalidFlags);
    assert_eq!(validate(abi::GLYPH_INDEX, 0, 0x2000, 1, 0, 1252).unwrap_err(), Error::InvalidCodePage);
    assert_eq!(validate(abi::GLYPH_INDEX, 0, u64::MAX - 1, 1, 0, 0).unwrap_err(), Error::MissingText);
    assert_eq!(validate(abi::GLYPH_INDEX, 0, 0x2000, 1, u64::MAX - 1, 0).unwrap_err(), Error::Overflow);
}
