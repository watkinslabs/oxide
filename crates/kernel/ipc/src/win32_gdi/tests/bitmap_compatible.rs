//! Bitmaps shaped after a device context.
use super::super::{GdiManager, GdiError, DibHeader, DIB_RGB_COLORS, BI_RGB, Rgb};

fn info_header(width: i32, height: i32, bit_count: u16) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[0..4].copy_from_slice(&40u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&width.to_le_bytes());
    bytes[8..12].copy_from_slice(&height.to_le_bytes());
    bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&bit_count.to_le_bytes());
    bytes[16..20].copy_from_slice(&BI_RGB.to_le_bytes());
    bytes
}

#[test]
fn a_display_context_supplies_the_devices_own_planes_and_depth() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_display_dc(8, 8).unwrap();
    let handle = gdi.create_compatible_bitmap(dc, 4, 3, 1, 32).unwrap();
    let bitmap = gdi.bitmap(handle).unwrap();
    assert_eq!((bitmap.width, bitmap.height, bitmap.bpp, bitmap.planes), (4, 3, 32, 1));
    assert!(bitmap.dib.is_none());
}

#[test]
fn a_memory_context_that_selected_nothing_produces_a_monochrome_bitmap() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(8, 8).unwrap();
    let handle = gdi.create_compatible_bitmap(dc, 4, 3, 1, 32).unwrap();
    assert_eq!(gdi.bitmap(handle).unwrap().bpp, 1);
}

#[test]
fn a_selected_device_dependent_bitmap_supplies_its_own_depth() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(8, 8).unwrap();
    let selected = gdi.create_bitmap(2, 2, 1, 32, None).unwrap();
    gdi.select_bitmap(dc, selected).unwrap();
    let handle = gdi.create_compatible_bitmap(dc, 4, 3, 1, 1).unwrap();
    let bitmap = gdi.bitmap(handle).unwrap();
    assert_eq!((bitmap.width, bitmap.height, bitmap.bpp), (4, 3, 32));
    assert!(bitmap.dib.is_none());
}

#[test]
fn a_selected_section_supplies_its_header_and_colour_table_at_the_new_extents() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(8, 8).unwrap();
    let header = DibHeader::parse(&info_header(2, 2, 8)).unwrap();
    let table = [Rgb { red: 1, green: 2, blue: 3 }];
    let selected = gdi.create_dib_section(header, DIB_RGB_COLORS, &table, [0; 3]).unwrap();
    gdi.select_bitmap(dc, selected).unwrap();
    let handle = gdi.create_compatible_bitmap(dc, 5, 6, 1, 32).unwrap();
    let bitmap = gdi.bitmap(handle).unwrap();
    assert_eq!((bitmap.width, bitmap.height, bitmap.bpp), (5, 6, 8));
    assert!(bitmap.dib.is_some());
    assert_eq!(bitmap.color_table()[0], Rgb { red: 1, green: 2, blue: 3 });
}

#[test]
fn an_empty_extent_or_an_unknown_context_produces_no_bitmap() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(8, 8).unwrap();
    assert_eq!(gdi.create_compatible_bitmap(dc, 0, 3, 1, 32), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.create_compatible_bitmap(dc, 4, 0, 1, 32), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.create_compatible_bitmap(99, 4, 3, 1, 32), Err(GdiError::NoSuchObject));
}
