//! Device-independent image transfers and their row banding.
use super::*;
use crate::win32_gdi::{GdiManager, GdiError, BI_RGB, SharedDcColors, BltCoords, SRCCOPY, COLORONCOLOR};

fn header(width: i32, height: i32, bit_count: u16) -> DibHeader {
    let mut bytes = [0u8; 40];
    bytes[0..4].copy_from_slice(&40u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&width.to_le_bytes());
    bytes[8..12].copy_from_slice(&height.to_le_bytes());
    bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&bit_count.to_le_bytes());
    bytes[16..20].copy_from_slice(&BI_RGB.to_le_bytes());
    DibHeader::parse(&bytes).unwrap()
}

fn colors() -> SharedDcColors { SharedDcColors { brush: 0, text: 0, background: 0x00ff_ffff, background_mode: 2 } }

#[test]
fn a_bottom_up_image_reads_its_last_stored_row_as_the_top_display_row() {
    let head = header(1, 2, 32);
    // Stored rows run bottom first: the second stored row is the top one.
    let bits = [0xff, 0, 0, 0, 0, 0xff, 0, 0];
    let image = DibImage { header: &head, table: &[], masks: crate::win32_gdi::default_masks(32), bits: &bits };
    assert_eq!(image.pixel(0, 0), Some(0x0000_ff00));
    assert_eq!(image.pixel(0, 1), Some(0x0000_00ff));
    assert_eq!(image.pixel(0, 2), None);
    let top_down = header(1, -2, 32);
    let flipped = DibImage { header: &top_down, table: &[], masks: crate::win32_gdi::default_masks(32), bits: &bits };
    assert_eq!(flipped.pixel(0, 0), Some(0x0000_00ff));
    assert_eq!(flipped.pixel(0, 1), Some(0x0000_ff00));
}

#[test]
fn the_transfer_band_selects_the_rows_the_scan_line_and_count_name() {
    // A bottom-up image counts its band from the last row up.
    assert_eq!(transfer_band(false, 4, 0, 4), (0, 0, 4, 4));
    assert_eq!(transfer_band(false, 4, 0, 2), (0, 2, 4, 2));
    assert_eq!(transfer_band(false, 4, 1, 4), (-1, 1, 4, 3));
    // A scan line past the image selects an empty band.
    assert_eq!(transfer_band(false, 4, 4, 4), (-4, 4, 4, 0));
    // A top-down image counts from the first, and is not limited by height.
    assert_eq!(transfer_band(true, 4, 0, 4), (0, 0, 4, 4));
    assert_eq!(transfer_band(true, 4, 0, 2), (2, 0, 2, 2));
    assert_eq!(transfer_band(true, 4, 1, 2), (1, 0, 2, 2));
}

#[test]
fn caller_rows_land_in_the_bitmap_and_read_back_through_a_query() {
    let mut gdi = GdiManager::new();
    let bitmap = gdi.create_bitmap(2, 2, 1, 32, None).unwrap();
    let head = header(2, 2, 32);
    let masks = crate::win32_gdi::default_masks(32);
    // Stored rows run bottom first, so the second stored row displays on top.
    let mut bits = [0u8; 16];
    for (index, word) in [1u32, 2, 3, 4].iter().enumerate() { bits[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes()); }
    assert_eq!(gdi.put_dib_rows(bitmap, &head, &[], masks, &bits, 0, 2), Ok(2));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 0), Some(3));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(1, 0), Some(4));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 1), Some(1));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(1, 1), Some(2));
    let mut out = [0u8; 16];
    assert_eq!(gdi.take_dib_rows(bitmap, &head, &[], masks, &mut out, 0, 2), Ok(2));
    assert_eq!(out, bits);
}

#[test]
fn a_short_row_count_transfers_only_its_band() {
    let mut gdi = GdiManager::new();
    let bitmap = gdi.create_bitmap(1, 4, 1, 32, None).unwrap();
    let head = header(1, 4, 32);
    let masks = crate::win32_gdi::default_masks(32);
    let bits = [1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0];
    // The scan line counts from the image's first stored row, which is its
    // bottom one, so two rows land at the bottom of the bitmap.
    assert_eq!(gdi.put_dib_rows(bitmap, &head, &[], masks, &bits, 0, 2), Ok(2));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 0), Some(0));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 1), Some(0));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 2), Some(2));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 3), Some(1));
    assert_eq!(gdi.put_dib_rows(bitmap, &head, &[], masks, &bits, 4, 2), Ok(0));
}

#[test]
fn a_query_reports_the_bitmaps_own_shape() {
    let mut gdi = GdiManager::new();
    let bitmap = gdi.create_bitmap(3, 5, 1, 32, None).unwrap();
    let head = gdi.dib_query_header(bitmap).unwrap();
    assert_eq!((head.width, head.height, head.bit_count, head.planes), (3, 5, 32, 1));
    assert_eq!(head.compression, crate::win32_gdi::BI_BITFIELDS);
    assert_eq!(head.size_image, 60);
    assert_eq!(head.clr_used, 0);
    let indexed = gdi.create_bitmap(2, 2, 1, 8, None).unwrap();
    let head = gdi.dib_query_header(indexed).unwrap();
    assert_eq!(head.compression, BI_RGB);
    assert_eq!(head.clr_used, 256);
    assert_eq!(gdi.dib_query_header(99), Err(GdiError::NoSuchObject));
}

#[test]
fn an_indexed_image_resolves_through_the_colour_table_the_caller_supplied() {
    let mut gdi = GdiManager::new();
    let bitmap = gdi.create_bitmap(2, 1, 1, 32, None).unwrap();
    let head = header(2, 1, 8);
    let table = [Rgb { red: 0x11, green: 0x22, blue: 0x33 }, Rgb { red: 0x44, green: 0x55, blue: 0x66 }];
    // Eight-bit rows pad to four bytes.
    let bits = [0, 1, 0, 0];
    assert_eq!(gdi.put_dib_rows(bitmap, &head, &table, [0; 3], &bits, 0, 1), Ok(1));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(0, 0), Some(0x0011_2233));
    assert_eq!(gdi.bitmap(bitmap).unwrap().pixel(1, 0), Some(0x0044_5566));
}

#[test]
fn a_caller_image_draws_straight_onto_a_device_context() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 1).unwrap();
    let head = header(2, 1, 32);
    let masks = crate::win32_gdi::default_masks(32);
    let bits = [0, 0, 0xff, 0, 0, 0xff, 0, 0];
    let whole = BltCoords { x: 0, y: 0, width: 2, height: 1 };
    assert_eq!(gdi.draw_dib(dc, whole, whole, &head, &[], masks, &bits, 0, 1, SRCCOPY, colors(), COLORONCOLOR), Ok(1));
    assert_eq!(gdi.pixels(dc).unwrap(), &[0x00ff_0000, 0x0000_ff00]);
    assert_eq!(gdi.draw_dib(99, whole, whole, &head, &[], masks, &bits, 0, 1, SRCCOPY, colors(), COLORONCOLOR), Err(GdiError::NoSuchObject));
}
