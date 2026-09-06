use super::*;

#[test]
fn hfont_create_accepts_only_three_concrete_struct_sizes() {
    for size in 0..=421 {
        let expected = matches!(size, 92 | 348 | 420);
        assert_eq!(valid_hfont_create_size(size), expected, "size {size}");
        assert_eq!(validate_hfont_create(0x10000, size).is_ok(), expected);
    }
    for size in [u32::MAX, 0x80000000] {
        assert_eq!(validate_hfont_create(0x10000, size), Err(FontCreateError::InvalidSize));
    }
}

#[test]
fn null_font_input_precedes_size_error_and_preserves_last_error() {
    for size in [0, 92, 348, 420, u32::MAX] {
        let error = validate_hfont_create(0, size).unwrap_err();
        assert_eq!(error, FontCreateError::NullInput);
        assert_eq!(error.last_error(), None);
    }
    assert_eq!(validate_hfont_create(0x10000, 0).unwrap_err().last_error(), Some(87));
    assert_eq!(validate_hfont_create(0x10000, 93).unwrap_err().last_error(), Some(87));
}

#[test]
fn raw_object_query_requires_three_arguments_and_preserves_negative_count() {
    assert_eq!(decode(0x11c7, &[0x0a0040, 0xffff_ffff, 0x10000]), Some(Query { handle: 0x0a0040, count: -1, output: 0x10000 }));
    assert_eq!(decode(0x11c7, &[0x0a0040, 0, 0]), Some(Query { handle: 0x0a0040, count: 0, output: 0 }));
    assert_eq!(decode(0x11c7, &[1, 2]), None);
    assert_eq!(decode(0x11c8, &[1, 2, 3]), None);
}
