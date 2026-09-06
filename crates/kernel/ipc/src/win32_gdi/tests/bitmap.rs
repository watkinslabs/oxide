use super::*;
use crate::win32_gdi::{BrushStyle, TYPE_BRUSH};

/// The 8x8 monochrome pattern a shell paints its focus and disabled surfaces with.
const GRAY_PATTERN: [u8; 16] = [0x55, 0x55, 0xaa, 0xaa, 0x55, 0x55, 0xaa, 0xaa, 0x55, 0x55, 0xaa, 0xaa, 0x55, 0x55, 0xaa, 0xaa];

#[test]
fn strides_align_stored_rows_to_32_bits_and_caller_rows_to_16() {
    assert_eq!(bitmap_stride(8, 1), Some(2));
    assert_eq!(dib_stride(8, 1), Some(4));
    assert_eq!(bitmap_stride(17, 1), Some(4));
    assert_eq!(dib_stride(17, 1), Some(4));
    assert_eq!(bitmap_stride(3, 24), Some(10));
    assert_eq!(dib_stride(3, 24), Some(12));
    assert_eq!(dib_stride(i32::MAX, 32), None);
}

#[test]
fn requested_depth_rounds_up_to_a_stored_depth() {
    for (requested, stored) in [(1, 1), (0, 4), (2, 4), (4, 4), (5, 8), (8, 8), (9, 16), (16, 16), (17, 24), (24, 24), (25, 32), (32, 32)] {
        assert_eq!(normalize_bpp(requested), Some(stored), "bpp {requested}");
    }
    assert_eq!(normalize_bpp(33), None);
}

#[test]
fn create_bitmap_admission_order_is_extent_then_planes_then_depth() {
    let mut gdi = GdiManager::new();
    // An oversized extent is refused even though the plane count is also wrong.
    assert_eq!(gdi.create_bitmap(0x800_0000, 8, 3, 1, None), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.create_bitmap(0, 8, 1, 1, None), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.create_bitmap(8, 0, 1, 1, None), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.create_bitmap(8, 8, 2, 1, None), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.create_bitmap(8, 8, 1, 33, None), Err(GdiError::InvalidDimensions));
    assert!(gdi.create_bitmap(8, 8, 1, 1, None).is_ok());
}

#[test]
fn negative_extents_take_their_magnitude() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_bitmap(-8, -4, 1, 1, None).unwrap();
    let bitmap = gdi.bitmap(handle).unwrap();
    assert_eq!((bitmap.width, bitmap.height), (8, 4));
    assert_eq!(gdi.create_bitmap(i32::MIN, 4, 1, 1, None), Err(GdiError::InvalidDimensions));
}

#[test]
fn bitmap_handles_carry_the_bitmap_object_type_and_project_as_live() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_bitmap(8, 8, 1, 1, None).unwrap();
    assert_eq!(handle & 0x00ff_0000, TYPE_BITMAP);
    assert!(gdi.contains_object(handle));
    assert!(gdi.live_handles().contains(&handle));
    assert_eq!(gdi.delete_object(handle), Ok(()));
    assert!(!gdi.contains_object(handle));
    assert_eq!(gdi.delete_object(handle), Err(GdiError::NoSuchObject));
}

#[test]
fn caller_rows_land_on_stored_rows_at_the_wider_stride() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_bitmap(8, 8, 1, 1, Some(&GRAY_PATTERN)).unwrap();
    let bitmap = gdi.bitmap(handle).unwrap();
    assert_eq!((bitmap.width_bytes, bitmap.bits().len()), (2, 32));
    assert_eq!(&bitmap.bits()[0..4], &[0x55, 0x55, 0, 0]);
    assert_eq!(&bitmap.bits()[4..8], &[0xaa, 0xaa, 0, 0]);
}

#[test]
fn a_short_caller_buffer_fills_only_the_rows_it_covers() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_bitmap(8, 8, 1, 1, Some(&GRAY_PATTERN[..4])).unwrap();
    let bitmap = gdi.bitmap(handle).unwrap();
    assert_eq!(&bitmap.bits()[0..4], &[0x55, 0x55, 0, 0]);
    assert_eq!(&bitmap.bits()[4..8], &[0xaa, 0xaa, 0, 0]);
    assert_eq!(&bitmap.bits()[8..12], &[0, 0, 0, 0]);
}

#[test]
fn a_monochrome_pattern_names_the_destination_text_and_background_colors() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_bitmap(8, 8, 1, 1, Some(&GRAY_PATTERN)).unwrap();
    let pattern = gdi.bitmap_pattern(handle).unwrap();
    assert_eq!(pattern.pixel(0, 0, 0x00ff_0000, 0x0000_00ff), Some(0x00ff_0000));
    assert_eq!(pattern.pixel(1, 0, 0x00ff_0000, 0x0000_00ff), Some(0x0000_00ff));
    assert_eq!(pattern.pixel(0, 1, 0x00ff_0000, 0x0000_00ff), Some(0x0000_00ff));
    assert_eq!(pattern.pixel(8, 0, 0, 0), None);
}

#[test]
fn color_pattern_depths_decode_to_xrgb_and_indexed_depths_do_not() {
    let mut gdi = GdiManager::new();
    let direct = gdi.create_bitmap(1, 1, 1, 32, Some(&[0x44, 0x33, 0x22, 0x11])).unwrap();
    assert_eq!(gdi.bitmap_pattern(direct).unwrap().pixel(0, 0, 0, 0), Some(0x0022_3344));
    let packed = gdi.create_bitmap(1, 1, 1, 24, Some(&[0x44, 0x33, 0x22, 0x00])).unwrap();
    assert_eq!(gdi.bitmap_pattern(packed).unwrap().pixel(0, 0, 0, 0), Some(0x0022_3344));
    // 5-bit channels replicate their high bits: 0x7c00 is full red.
    let high = gdi.create_bitmap(1, 1, 1, 16, Some(&[0x00, 0x7c])).unwrap();
    assert_eq!(gdi.bitmap_pattern(high).unwrap().pixel(0, 0, 0, 0), Some(0x00ff_0000));
    let indexed = gdi.create_bitmap(2, 1, 1, 8, Some(&[0x01, 0x02])).unwrap();
    assert_eq!(gdi.bitmap_pattern(indexed).unwrap().pixel(0, 0, 0, 0), None);
}

#[test]
fn a_pattern_brush_keeps_painting_after_its_bitmap_is_deleted() {
    let mut gdi = GdiManager::new();
    let bitmap = gdi.create_bitmap(8, 8, 1, 1, Some(&GRAY_PATTERN)).unwrap();
    let brush = gdi.create_pattern_brush(bitmap).unwrap();
    assert_eq!(brush & 0x00ff_0000, TYPE_BRUSH);
    assert_eq!(gdi.brush_style(brush, 0), Ok(BrushStyle::Pattern));
    assert_eq!(gdi.delete_object(bitmap), Ok(()));
    assert!(gdi.brush_pattern(brush).is_some());
    assert_eq!(gdi.create_pattern_brush(bitmap), Err(GdiError::NoSuchObject));
}
