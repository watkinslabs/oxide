use super::*;
use crate::win32_gdi::{GdiManager, Rect};

fn setup() -> (GdiManager, u32) { let mut g = GdiManager::new(); let dc = g.create_dc(8, 8).unwrap(); (g, dc) }

#[test]
fn filling_paints_only_the_region_coverage_with_the_named_brush() {
    let (mut g, dc) = setup();
    let region = g.create_rect_region(Rect { left: 2, top: 2, right: 5, bottom: 5 }).unwrap();
    let brush = g.create_solid_brush(0x00ff_0000).unwrap();
    assert_eq!(g.fill_region(dc, region, brush), Ok(()));
    let px = |x: usize, y: usize| g.pixels(dc).unwrap()[y * 8 + x];
    assert_eq!(px(3, 3), 0x00ff_0000);
    assert_eq!(px(1, 3), 0);
    assert_eq!(px(5, 3), 0);
}

#[test]
fn filling_restores_the_previously_selected_brush() {
    let (mut g, dc) = setup();
    let region = g.create_rect_region(Rect { left: 0, top: 0, right: 2, bottom: 2 }).unwrap();
    let selected = g.create_solid_brush(0x0000_00ff).unwrap();
    let other = g.create_solid_brush(0x0000_ff00).unwrap();
    let before = g.select_brush(dc, selected).unwrap();
    g.fill_region(dc, region, other).unwrap();
    assert_eq!(g.select_brush(dc, before), Ok(selected));
}

#[test]
fn a_hole_in_the_region_is_left_unpainted() {
    let (mut g, dc) = setup();
    let outer = g.create_rect_region(Rect { left: 0, top: 0, right: 8, bottom: 8 }).unwrap();
    let inner = g.create_rect_region(Rect { left: 3, top: 3, right: 5, bottom: 5 }).unwrap();
    g.combine_region(outer, outer, inner, crate::win32_gdi::RGN_DIFF).unwrap();
    let brush = g.create_solid_brush(0x0011_2233).unwrap();
    g.fill_region(dc, outer, brush).unwrap();
    assert_eq!(g.pixels(dc).unwrap()[3 * 8 + 3], 0);
    assert_eq!(g.pixels(dc).unwrap()[0], 0x0011_2233);
}

#[test]
fn a_frame_paints_the_border_and_leaves_the_interior() {
    let (mut g, dc) = setup();
    let region = g.create_rect_region(Rect { left: 1, top: 1, right: 7, bottom: 7 }).unwrap();
    let brush = g.create_solid_brush(0x0000_ff00).unwrap();
    assert_eq!(g.frame_region(dc, region, brush, 1, 1), Ok(()));
    let px = |x: usize, y: usize| g.pixels(dc).unwrap()[y * 8 + x];
    assert_eq!(px(1, 1), 0x0000_ff00);
    assert_eq!(px(6, 6), 0x0000_ff00);
    assert_eq!(px(3, 3), 0);
    assert_eq!(px(0, 0), 0);
}

#[test]
fn inverting_complements_the_covered_pixels_and_is_its_own_inverse() {
    let (mut g, dc) = setup();
    g.fill_rect(dc, Rect { left: 0, top: 0, right: 8, bottom: 8 }, 0x0012_3456).unwrap();
    let region = g.create_rect_region(Rect { left: 0, top: 0, right: 4, bottom: 4 }).unwrap();
    g.invert_region(dc, region).unwrap();
    assert_eq!(g.pixels(dc).unwrap()[0], !0x0012_3456 & 0x00ff_ffff);
    assert_eq!(g.pixels(dc).unwrap()[5], 0x0012_3456);
    g.invert_region(dc, region).unwrap();
    assert_eq!(g.pixels(dc).unwrap()[0], 0x0012_3456);
}

#[test]
fn region_drawing_is_clipped_by_the_device_context_clip() {
    let (mut g, dc) = setup();
    g.intersect_clip_rect(dc, Rect { left: 0, top: 0, right: 2, bottom: 8 }).unwrap();
    let region = g.create_rect_region(Rect { left: 0, top: 0, right: 8, bottom: 8 }).unwrap();
    let brush = g.create_solid_brush(0x0000_00ff).unwrap();
    g.fill_region(dc, region, brush).unwrap();
    assert_eq!(g.pixels(dc).unwrap()[0], 0x0000_00ff);
    assert_eq!(g.pixels(dc).unwrap()[3], 0);
}

#[test]
fn unknown_region_and_empty_frame_sources_are_refused() {
    let (mut g, dc) = setup();
    let brush = g.create_solid_brush(0).unwrap();
    assert_eq!(g.fill_region(dc, 99, brush), Err(GdiError::NoSuchObject));
    assert_eq!(g.invert_region(dc, 99), Err(GdiError::NoSuchObject));
    let empty = g.create_rect_region(Rect { left: 0, top: 0, right: 0, bottom: 0 }).unwrap();
    assert_eq!(g.frame_region(dc, empty, brush, 1, 1), Err(GdiError::NoSuchObject));
}
