use super::*;

#[test]
fn create_bitmap_takes_five_windows_scalars_and_ignores_register_high_halves() {
    assert_eq!(decode(CREATE_BITMAP, &[0xdead_0000_0000_0008, 0x8, 1, 1, 0x7fff_0000]),
        Some(Operation::CreateBitmap { width: 8, height: 8, planes: 1, bpp: 1, bits: 0x7fff_0000 }));
    // A negative extent survives the 32-bit narrowing as a negative extent.
    assert_eq!(decode(CREATE_BITMAP, &[0xffff_fff8, 4, 1, 32, 0]),
        Some(Operation::CreateBitmap { width: -8, height: 4, planes: 1, bpp: 32, bits: 0 }));
    assert_eq!(decode(CREATE_BITMAP, &[8, 8, 1, 1]), None);
}

#[test]
fn pattern_brush_names_one_bitmap_and_open_dc_turns_on_the_display_flag() {
    assert_eq!(decode(CREATE_PATTERN_BRUSH, &[0x9_0040, 0, 0]), Some(Operation::CreatePatternBrush { bitmap: 0x9_0040 }));
    assert_eq!(decode(CREATE_PATTERN_BRUSH, &[0x9_0040, 0]), None);
    assert_eq!(decode(OPEN_DC_W, &[0, 0, 0, 0, 1]), Some(Operation::OpenDisplayDc));
    assert_eq!(decode(OPEN_DC_W, &[0x7fff_0000, 0, 0, 0, 1]), Some(Operation::OpenDisplayDc));
    // Without the display flag the call needs a printer or metafile driver.
    assert_eq!(decode(OPEN_DC_W, &[0, 0, 0, 0, 0]), Some(Operation::NoDriverDc));
    assert_eq!(decode(OPEN_DC_W, &[0, 0, 0, 0]), None);
}

#[test]
fn unrelated_ordinals_are_not_claimed_here() {
    for ordinal in [0x10a6, 0x10a8, 0x10b8, 0x10ba, 0x1245, 0x1247, 0x10bf] {
        assert_eq!(decode(ordinal, &[0; 6]), None, "ordinal {ordinal:#x}");
    }
}

#[test]
fn caller_bits_are_measured_at_the_16_bit_aligned_row_stride() {
    // Eight monochrome rows of two bytes, not the four-byte stored stride.
    assert_eq!(caller_bits_len(8, 8, 1, 1, 0x1000), Some(16));
    assert_eq!(caller_bits_len(-8, -8, 1, 1, 0x1000), Some(16));
    assert_eq!(caller_bits_len(1, 1, 1, 32, 0x1000), Some(4));
    assert_eq!(caller_bits_len(3, 2, 1, 24, 0x1000), Some(20));
    // A rounded-up depth measures at the depth actually stored.
    assert_eq!(caller_bits_len(8, 1, 1, 5, 0x1000), Some(8));
}

#[test]
fn no_bits_are_fetched_without_a_pointer_or_for_an_inadmissible_request() {
    assert_eq!(caller_bits_len(8, 8, 1, 1, 0), None);
    assert_eq!(caller_bits_len(8, 8, 2, 1, 0x1000), None);
    assert_eq!(caller_bits_len(8, 8, 1, 33, 0x1000), None);
    assert_eq!(caller_bits_len(i32::MIN, 8, 1, 1, 0x1000), None);
    assert_eq!(caller_bits_len(0x7ff_ffff, 0x7ff_ffff, 1, 32, 0x1000), None);
}
