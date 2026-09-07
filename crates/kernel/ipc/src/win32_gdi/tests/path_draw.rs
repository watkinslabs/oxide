use super::*;
use crate::win32_gdi::{GdiManager, Rect};

fn setup() -> (GdiManager, u32) { let mut g = GdiManager::new(); let dc = g.create_dc(10, 10).unwrap(); (g, dc) }

fn square(g: &mut GdiManager, dc: u32) {
    g.begin_path(dc).unwrap();
    g.path_rectangle(dc, 2, 2, 8, 8).unwrap();
    g.end_path(dc).unwrap();
}

#[test]
fn filling_paints_the_interior_with_the_selected_brush_and_consumes_the_path() {
    let (mut g, dc) = setup();
    let brush = g.create_solid_brush(0x0000_ff00).unwrap();
    g.select_brush(dc, brush).unwrap();
    square(&mut g, dc);
    assert_eq!(g.fill_path(dc), Ok(()));
    assert_eq!(g.pixels(dc).unwrap()[5 * 10 + 5], 0x0000_ff00);
    assert_eq!(g.pixels(dc).unwrap()[0], 0);
    assert_eq!(g.fill_path(dc), Err(GdiError::InvalidDimensions));
}

#[test]
fn stroking_paints_the_outline_and_leaves_the_interior() {
    let (mut g, dc) = setup();
    let pen = g.create_pen(0, 1, 0x00ff_0000).unwrap();
    g.select_pen(dc, pen).unwrap();
    square(&mut g, dc);
    assert_eq!(g.stroke_path(dc), Ok(()));
    assert_eq!(g.pixels(dc).unwrap()[2 * 10 + 2], 0x00ff_0000);
    assert_eq!(g.pixels(dc).unwrap()[5 * 10 + 5], 0);
    assert_eq!(g.stroke_path(dc), Err(GdiError::InvalidDimensions));
}

#[test]
fn stroking_and_filling_paints_both_the_interior_and_the_outline() {
    let (mut g, dc) = setup();
    let brush = g.create_solid_brush(0x0000_00ff).unwrap();
    let pen = g.create_pen(0, 1, 0x00ff_0000).unwrap();
    g.select_brush(dc, brush).unwrap();
    g.select_pen(dc, pen).unwrap();
    square(&mut g, dc);
    assert_eq!(g.stroke_and_fill_path(dc), Ok(()));
    assert_eq!(g.pixels(dc).unwrap()[5 * 10 + 5], 0x0000_00ff);
    assert_eq!(g.pixels(dc).unwrap()[2 * 10 + 2], 0x00ff_0000);
}

#[test]
fn drawing_a_path_that_was_never_closed_is_refused_without_painting() {
    let (mut g, dc) = setup();
    let brush = g.create_solid_brush(0x0011_2233).unwrap();
    g.select_brush(dc, brush).unwrap();
    g.begin_path(dc).unwrap();
    g.path_rectangle(dc, 0, 0, 10, 10).unwrap();
    assert_eq!(g.fill_path(dc), Err(GdiError::InvalidDimensions));
    assert_eq!(g.stroke_and_fill_path(dc), Err(GdiError::InvalidDimensions));
    assert_eq!(g.pixels(dc).unwrap()[0], 0);
}

#[test]
fn the_device_context_clip_bounds_what_a_path_paints() {
    let (mut g, dc) = setup();
    let brush = g.create_solid_brush(0x0000_ff00).unwrap();
    g.select_brush(dc, brush).unwrap();
    g.intersect_clip_rect(dc, Rect { left: 0, top: 0, right: 5, bottom: 10 }).unwrap();
    square(&mut g, dc);
    g.fill_path(dc).unwrap();
    assert_eq!(g.pixels(dc).unwrap()[5 * 10 + 3], 0x0000_ff00);
    assert_eq!(g.pixels(dc).unwrap()[5 * 10 + 6], 0);
}
