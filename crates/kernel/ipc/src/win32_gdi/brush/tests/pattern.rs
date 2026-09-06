use super::*;
use crate::win32_gdi::{GdiManager, Rect};

const PATCOPY: u32 = 0x00f0_0021;
const COLORS: SharedDcColors = SharedDcColors { brush: 0, text: 0x0011_2233, background: 0x0044_5566 };
/// Two rows of a 2x2 monochrome checker: 0b10.. then 0b01.., 32-bit aligned.
const CHECKER: [u8; 4] = [0x80, 0x00, 0x40, 0x00];

fn checker(gdi: &mut GdiManager) -> u32 {
    let bitmap = gdi.create_bitmap(2, 2, 1, 1, Some(&CHECKER)).unwrap();
    gdi.create_pattern_brush(bitmap).unwrap()
}

#[test]
fn a_solid_style_fills_every_cell_with_one_color() {
    let fill = fill(BrushStyle::Solid(0x0012_3456), None, COLORS).unwrap();
    assert_eq!(fill.color(0, 0), 0x0012_3456);
    assert_eq!(fill.color(-7, 91), 0x0012_3456);
}

#[test]
fn a_pattern_tiles_from_the_device_origin_in_both_directions() {
    let mut gdi = GdiManager::new();
    let brush = checker(&mut gdi);
    let fill = fill(BrushStyle::Pattern, gdi.brush_pattern(brush), COLORS).unwrap();
    assert_eq!(fill.color(0, 0), COLORS.background);
    assert_eq!(fill.color(1, 0), COLORS.text);
    assert_eq!(fill.color(0, 1), COLORS.text);
    assert_eq!(fill.color(2, 2), COLORS.background);
    assert_eq!(fill.color(-2, -2), COLORS.background);
    assert_eq!(fill.color(-1, 0), COLORS.text);
}

#[test]
fn an_unresolvable_pattern_depth_fails_before_any_pixel_is_written() {
    let mut gdi = GdiManager::new();
    let bitmap = gdi.create_bitmap(2, 1, 1, 8, Some(&[1, 2])).unwrap();
    let brush = gdi.create_pattern_brush(bitmap).unwrap();
    let dc = gdi.create_dc(2, 1).unwrap();
    gdi.fill_rect(dc, Rect { left: 0, top: 0, right: 2, bottom: 1 }, 0x0000_00ff).unwrap();
    gdi.select_brush(dc, brush).unwrap();
    assert_eq!(gdi.pat_blt(dc, 0, 0, 2, 1, PATCOPY), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.pixels(dc).unwrap(), &[0x0000_00ff, 0x0000_00ff]);
}

#[test]
fn pat_blt_through_a_pattern_brush_paints_the_tiled_cells() {
    let mut gdi = GdiManager::new();
    let brush = checker(&mut gdi);
    let dc = gdi.create_dc(2, 2).unwrap();
    gdi.select_brush(dc, brush).unwrap();
    gdi.pat_blt(dc, 0, 0, 2, 2, PATCOPY).unwrap();
    // A fresh DC's text and background attributes supply the two indices.
    let (text, background) = (gdi.pixels(dc).unwrap()[1], gdi.pixels(dc).unwrap()[0]);
    assert_ne!(text, background);
    assert_eq!(gdi.pixels(dc).unwrap(), &[background, text, text, background]);
}
