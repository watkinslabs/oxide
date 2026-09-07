//! Single-pixel access and flood fill.
use super::*;
use crate::win32_gdi::{GdiManager, GdiError, CLR_INVALID, SharedDcColors, Rect};

fn colors() -> SharedDcColors { SharedDcColors { brush: 0, text: 0, background: 0x00ff_ffff, background_mode: 2 } }

#[test]
fn a_stored_pixel_reads_back_and_a_position_outside_the_surface_is_invalid() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    assert_eq!(gdi.set_pixel(dc, 1, 1, 0x0012_3456), Ok(0x0012_3456));
    assert_eq!(gdi.get_pixel(dc, 1, 1), Ok(0x0012_3456));
    assert_eq!(gdi.get_pixel(dc, 0, 0), Ok(0));
    assert_eq!(gdi.set_pixel(dc, 5, 0, 1), Ok(CLR_INVALID));
    assert_eq!(gdi.get_pixel(dc, 5, 0), Ok(CLR_INVALID));
    assert_eq!(gdi.get_pixel(99, 0, 0), Err(GdiError::NoSuchObject));
}

#[test]
fn a_pixel_stored_in_an_indexed_bitmap_reads_back_as_its_table_entry() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    let bitmap = gdi.create_bitmap(2, 2, 1, 1, None).unwrap();
    gdi.select_bitmap(dc, bitmap).unwrap();
    // A monochrome bitmap resolves the nearest of black and white.
    assert_eq!(gdi.set_pixel(dc, 0, 0, 0x00ee_ee_ee), Ok(0x00ff_ffff));
    assert_eq!(gdi.get_pixel(dc, 0, 0), Ok(0x00ff_ffff));
    assert_eq!(gdi.set_pixel(dc, 1, 0, 0x0011_1111), Ok(0));
}

#[test]
fn a_surface_fill_covers_the_connected_run_of_the_named_colour() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(4, 1).unwrap();
    gdi.blit_pixels(dc, 0, 0, 4, 1, 4, &[0, 0, 0x00ff_ffff, 0]).unwrap();
    let brush = gdi.create_solid_brush(0x0000_00ff).unwrap();
    gdi.select_brush(dc, brush).unwrap();
    gdi.ext_flood_fill(dc, 0, 0, 0, FLOODFILLSURFACE, colors()).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), &[0xff, 0xff, 0x00ff_ffff, 0]);
}

#[test]
fn a_border_fill_spreads_until_it_meets_the_border_colour() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(4, 1).unwrap();
    gdi.blit_pixels(dc, 0, 0, 4, 1, 4, &[0, 0x0011_1111, 0x00ff_0000, 0]).unwrap();
    let brush = gdi.create_solid_brush(0x0000_00ff).unwrap();
    gdi.select_brush(dc, brush).unwrap();
    gdi.ext_flood_fill(dc, 0, 0, 0x00ff_0000, FLOODFILLBORDER, colors()).unwrap();
    assert_eq!(gdi.pixels(dc).unwrap(), &[0xff, 0xff, 0x00ff_0000, 0]);
}

#[test]
fn a_seed_that_does_not_admit_the_fill_or_an_unknown_type_paints_nothing() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 1).unwrap();
    gdi.fill_rect(dc, Rect { left: 0, top: 0, right: 2, bottom: 1 }, 0x00ff_0000).unwrap();
    let brush = gdi.create_solid_brush(0x0000_00ff).unwrap();
    gdi.select_brush(dc, brush).unwrap();
    // A surface fill needs the seed to already hold the named colour.
    assert_eq!(gdi.ext_flood_fill(dc, 0, 0, 0, FLOODFILLSURFACE, colors()), Err(GdiError::InvalidDimensions));
    // A border fill needs the seed not to be the border colour.
    assert_eq!(gdi.ext_flood_fill(dc, 0, 0, 0x00ff_0000, FLOODFILLBORDER, colors()), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.ext_flood_fill(dc, 0, 0, 0, 9, colors()), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.ext_flood_fill(dc, 9, 9, 0, FLOODFILLSURFACE, colors()), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.pixels(dc).unwrap(), &[0x00ff_0000, 0x00ff_0000]);
}
