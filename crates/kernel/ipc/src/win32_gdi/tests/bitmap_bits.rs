//! Caller bit transfers at the 16-bit-aligned stride, and assigned dimensions.
use super::*;
use super::super::{GdiManager, GdiError};

#[test]
fn caller_stride_differs_from_storage_stride_and_transfers_row_by_row() {
    let mut gdi = GdiManager::new();
    // Three eight-bit pixels: caller rows are four bytes, storage rows four too.
    let bitmap = gdi.create_bitmap(3, 2, 1, 8, None).unwrap();
    assert_eq!(gdi.bitmap_bits_len(bitmap), Ok(8));
    assert_eq!(gdi.set_bitmap_bits(bitmap, 8, &[1, 2, 3, 0, 4, 5, 6, 0]), Ok(8));
    let mut out = [0u8; 8];
    assert_eq!(gdi.get_bitmap_bits(bitmap, 8, &mut out), Ok(8));
    assert_eq!(out, [1, 2, 3, 0, 4, 5, 6, 0]);
}

#[test]
fn one_bit_deep_rows_pad_to_two_bytes_for_the_caller_and_four_in_storage() {
    let mut gdi = GdiManager::new();
    let bitmap = gdi.create_bitmap(17, 2, 1, 1, None).unwrap();
    // Seventeen pixels need three bytes, rounded to four for the caller.
    assert_eq!(gdi.bitmap_bits_len(bitmap), Ok(8));
    assert_eq!(gdi.set_bitmap_bits(bitmap, 8, &[0x80, 0, 0x80, 0, 0x40, 0, 0, 0]), Ok(8));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 0), Some(0x00ff_ffff));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(16, 0), Some(0x00ff_ffff));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(1, 1), Some(0x00ff_ffff));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 1), Some(0));
}

#[test]
fn a_negative_or_oversized_count_reads_the_whole_bitmap() {
    let mut gdi = GdiManager::new();
    // Two eight-bit pixels pad to a two-byte caller row: four bytes in all.
    let bitmap = gdi.create_bitmap(2, 2, 1, 8, None).unwrap();
    let mut out = [0u8; 8];
    assert_eq!(gdi.get_bitmap_bits(bitmap, -1, &mut out), Ok(4));
    assert_eq!(gdi.get_bitmap_bits(bitmap, 99, &mut out), Ok(4));
    // A negative write count is taken as its magnitude.
    assert_eq!(gdi.set_bitmap_bits(bitmap, -4, &[9, 9, 9, 9]), Ok(4));
    assert_eq!(gdi.get_bitmap_bits(bitmap, 4, &mut out), Ok(4));
    assert_eq!(&out[..4], &[9, 9, 9, 9]);
}

#[test]
fn a_short_count_transfers_only_the_rows_it_covers() {
    let mut gdi = GdiManager::new();
    let bitmap = gdi.create_bitmap(4, 3, 1, 8, None).unwrap();
    assert_eq!(gdi.set_bitmap_bits(bitmap, 6, &[1, 2, 3, 4, 5, 6]), Ok(6));
    let mut out = [0xffu8; 12];
    assert_eq!(gdi.get_bitmap_bits(bitmap, 12, &mut out), Ok(12));
    assert_eq!(&out[..6], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(&out[6..], &[0; 6]);
}

#[test]
fn transfers_refuse_a_handle_that_names_no_bitmap() {
    let mut gdi = GdiManager::new();
    let mut out = [0u8; 4];
    assert_eq!(gdi.get_bitmap_bits(99, 4, &mut out), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.set_bitmap_bits(99, 4, &[0; 4]), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.bitmap_bits_len(99), Err(GdiError::NoSuchObject));
}

#[test]
fn assigned_dimension_starts_at_zero_and_reports_the_one_it_replaced() {
    let mut gdi = GdiManager::new();
    let bitmap = gdi.create_bitmap(2, 2, 1, 8, None).unwrap();
    assert_eq!(gdi.bitmap_dimension(bitmap), Ok((0, 0)));
    assert_eq!(gdi.set_bitmap_dimension(bitmap, 30, 40), Ok((0, 0)));
    assert_eq!(gdi.bitmap_dimension(bitmap), Ok((30, 40)));
    assert_eq!(gdi.set_bitmap_dimension(bitmap, -1, -2), Ok((30, 40)));
    assert_eq!(gdi.bitmap_dimension(bitmap), Ok((-1, -2)));
    assert_eq!(gdi.bitmap_dimension(99), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.set_bitmap_dimension(99, 1, 1), Err(GdiError::NoSuchObject));
}
