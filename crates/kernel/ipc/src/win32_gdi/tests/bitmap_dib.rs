//! DIB header admission, sections, and the selected DIB's colour table.
use super::*;
use super::super::{GdiManager, GdiError};

fn info_header(width: i32, height: i32, bit_count: u16, compression: u32) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[0..4].copy_from_slice(&40u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&width.to_le_bytes());
    bytes[8..12].copy_from_slice(&height.to_le_bytes());
    bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&bit_count.to_le_bytes());
    bytes[16..20].copy_from_slice(&compression.to_le_bytes());
    bytes
}

#[test]
fn a_core_header_supplies_unsigned_extents_and_no_compression() {
    let mut bytes = [0u8; 12];
    bytes[0..4].copy_from_slice(&12u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&4u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&3u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&8u16.to_le_bytes());
    let header = DibHeader::parse(&bytes).unwrap();
    assert_eq!((header.width, header.height, header.bit_count), (4, 3, 8));
    assert_eq!(header.compression, BI_RGB);
    // The size the caller supplied is replaced with the real image size.
    assert_eq!(header.size_image, 12);
    assert!(header.is_valid(false));
}

#[test]
fn an_info_header_keeps_its_fields_and_recomputes_the_image_size() {
    let mut bytes = info_header(3, -2, 32, BI_RGB);
    bytes[20..24].copy_from_slice(&999u32.to_le_bytes());
    let header = DibHeader::parse(&bytes).unwrap();
    assert_eq!(header.size_image, 24);
    assert!(header.top_down());
    assert_eq!(header.image_size(), Some(24));
    assert_eq!(DibHeader::parse(&bytes[..8]), None);
    // A size word between the two shapes names neither header.
    let mut short = info_header(3, 2, 32, BI_RGB);
    short[0..4].copy_from_slice(&20u32.to_le_bytes());
    assert_eq!(DibHeader::parse(&short), None);
}

#[test]
fn format_admission_rejects_empty_extents_and_depth_compression_mismatches() {
    assert!(!DibHeader::parse(&info_header(0, 2, 8, BI_RGB)).unwrap().is_valid(false));
    assert!(!DibHeader::parse(&info_header(-1, 2, 8, BI_RGB)).unwrap().is_valid(false));
    assert!(!DibHeader::parse(&info_header(2, 0, 8, BI_RGB)).unwrap().is_valid(false));
    assert!(!DibHeader::parse(&info_header(2, 2, 0, BI_RGB)).unwrap().is_valid(false));
    assert!(!DibHeader::parse(&info_header(2, 2, 7, BI_RGB)).unwrap().is_valid(false));
    // Only sixteen and thirty-two bits carry explicit channel masks.
    assert!(!DibHeader::parse(&info_header(2, 2, 8, BI_BITFIELDS)).unwrap().is_valid(false));
    assert!(!DibHeader::parse(&info_header(2, 2, 24, BI_BITFIELDS)).unwrap().is_valid(false));
    assert!(DibHeader::parse(&info_header(2, 2, 16, BI_BITFIELDS)).unwrap().is_valid(false));
    assert!(DibHeader::parse(&info_header(2, 2, 32, BI_BITFIELDS)).unwrap().is_valid(false));
    for depth in [1, 4, 8, 24] { assert!(DibHeader::parse(&info_header(2, 2, depth, BI_RGB)).unwrap().is_valid(false)); }
    // A plane count of zero fails before any stride arithmetic.
    let mut planeless = info_header(2, 2, 8, BI_RGB);
    planeless[12..14].copy_from_slice(&0u16.to_le_bytes());
    assert!(!DibHeader::parse(&planeless).unwrap().is_valid(false));
}

#[test]
fn run_length_compression_is_admitted_only_where_it_is_allowed() {
    let mut bytes = info_header(4, 4, 8, 1);
    bytes[20..24].copy_from_slice(&16u32.to_le_bytes());
    let header = DibHeader::parse(&bytes).unwrap();
    assert!(header.is_valid(true));
    assert!(!header.is_valid(false));
    // The depth must match the run-length flavour, and rows may not be top-down.
    let mut wrong = info_header(4, 4, 4, 1);
    wrong[20..24].copy_from_slice(&16u32.to_le_bytes());
    assert!(!DibHeader::parse(&wrong).unwrap().is_valid(true));
    let mut top_down = info_header(4, -4, 8, 1);
    top_down[20..24].copy_from_slice(&16u32.to_le_bytes());
    assert!(!DibHeader::parse(&top_down).unwrap().is_valid(true));
}

#[test]
fn colour_table_length_covers_the_whole_depth_and_clamps_a_caller_count() {
    let mut header = DibHeader::parse(&info_header(2, 2, 4, BI_RGB)).unwrap();
    assert_eq!(header.color_table_len(), 16);
    assert_eq!(header.supplied_colors(), 16);
    header.clr_used = 3;
    assert_eq!(header.supplied_colors(), 3);
    header.clr_used = 99;
    assert_eq!(header.supplied_colors(), 16);
    let deep = DibHeader::parse(&info_header(2, 2, 24, BI_RGB)).unwrap();
    assert_eq!(deep.color_table_len(), 0);
    assert_eq!(deep.supplied_colors(), 0);
}

#[test]
fn a_section_stores_its_header_table_and_masks() {
    let mut gdi = GdiManager::new();
    let header = DibHeader::parse(&info_header(4, -2, 8, BI_RGB)).unwrap();
    let table = [Rgb { red: 1, green: 2, blue: 3 }, Rgb { red: 4, green: 5, blue: 6 }];
    let handle = gdi.create_dib_section(header, DIB_RGB_COLORS, &table, [0; 3]).unwrap();
    let bitmap = gdi.bitmap(handle).unwrap();
    assert_eq!((bitmap.width, bitmap.height, bitmap.bpp), (4, 2, 8));
    assert_eq!(bitmap.color_table().len(), 256);
    assert_eq!(bitmap.color_table()[1], Rgb { red: 4, green: 5, blue: 6 });
    assert_eq!(bitmap.color_table()[2], Rgb::default());
    assert!(bitmap.dib.is_some());
    assert_eq!(bitmap.dib.unwrap().clr_used, 256);
}

#[test]
fn sixteen_bit_sections_gain_explicit_five_five_five_masks() {
    let mut gdi = GdiManager::new();
    let header = DibHeader::parse(&info_header(2, 2, 16, BI_RGB)).unwrap();
    let handle = gdi.create_dib_section(header, DIB_RGB_COLORS, &[], [0; 3]).unwrap();
    let bitmap = gdi.bitmap(handle).unwrap();
    assert_eq!(bitmap.dib.unwrap().compression, BI_BITFIELDS);
    assert_eq!(bitmap.masks(), [0x7c00, 0x03e0, 0x001f]);
}

#[test]
fn explicit_masks_are_taken_and_a_zero_mask_or_palette_usage_is_refused() {
    let mut gdi = GdiManager::new();
    let header = DibHeader::parse(&info_header(2, 2, 32, BI_BITFIELDS)).unwrap();
    let masks = [0x0000_00ff, 0x0000_ff00, 0x00ff_0000];
    let handle = gdi.create_dib_section(header, DIB_RGB_COLORS, &[], masks).unwrap();
    assert_eq!(gdi.bitmap(handle).unwrap().masks(), masks);
    assert_eq!(gdi.create_dib_section(header, DIB_RGB_COLORS, &[], [0x00ff_0000, 0, 0xff]), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.create_dib_section(header, DIB_PAL_COLORS, &[], masks), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.create_dib_section(header, 9, &[], masks), Err(GdiError::InvalidDimensions));
    let bad = DibHeader::parse(&info_header(0, 2, 32, BI_RGB)).unwrap();
    assert_eq!(gdi.create_dib_section(bad, DIB_RGB_COLORS, &[], masks), Err(GdiError::InvalidDimensions));
}

#[test]
fn the_selected_dib_owns_the_colour_table_a_device_context_reads_and_writes() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(4, 4).unwrap();
    let header = DibHeader::parse(&info_header(4, 2, 4, BI_RGB)).unwrap();
    let handle = gdi.create_dib_section(header, DIB_RGB_COLORS, &[], [0; 3]).unwrap();
    let mut out = [Rgb::default(); 4];
    // Nothing is selected yet, so there is no table to read.
    assert_eq!(gdi.get_dib_color_table(dc, 0, 4, &mut out), 0);
    gdi.select_bitmap(dc, handle).unwrap();
    assert_eq!(gdi.set_dib_color_table(dc, 1, 2, &[Rgb { red: 9, green: 8, blue: 7 }, Rgb { red: 6, green: 5, blue: 4 }]), 2);
    assert_eq!(gdi.get_dib_color_table(dc, 1, 4, &mut out), 4);
    assert_eq!(out[0], Rgb { red: 9, green: 8, blue: 7 });
    assert_eq!(out[1], Rgb { red: 6, green: 5, blue: 4 });
    assert_eq!(out[2], Rgb::default());
    // A start past the table copies nothing; a count past its end shortens.
    assert_eq!(gdi.get_dib_color_table(dc, 16, 1, &mut out), 0);
    assert_eq!(gdi.set_dib_color_table(dc, 16, 1, &[Rgb::default()]), 0);
    assert_eq!(gdi.set_dib_color_table(dc, 15, 4, &[Rgb { red: 1, green: 1, blue: 1 }]), 1);
}

#[test]
fn a_device_dependent_bitmap_has_no_device_context_colour_table() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(4, 4).unwrap();
    let bitmap = gdi.create_bitmap(4, 2, 1, 1, None).unwrap();
    gdi.select_bitmap(dc, bitmap).unwrap();
    let mut out = [Rgb::default(); 2];
    assert_eq!(gdi.get_dib_color_table(dc, 0, 2, &mut out), 0);
    assert_eq!(gdi.set_dib_color_table(dc, 0, 2, &[Rgb::default(); 2]), 0);
}
