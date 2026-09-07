use super::*;
use crate::win32_gdi::{PT_LINETO, PT_MOVETO};
use crate::win32_gdi::region::scan::Point;
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

#[test]
fn a_line_drawn_while_a_path_is_open_records_instead_of_rasterizing() {
    let (mut g, dc) = setup();
    let pen = g.create_pen(0, 1, 0x00ff_0000).unwrap();
    g.select_pen(dc, pen).unwrap();
    g.begin_path(dc).unwrap();
    g.set_text_position(dc, (1, 1)).unwrap();
    g.pen_line_to(dc, (8, 1), None).unwrap();
    // Nothing reached the surface, and the segment is in the path.
    assert!(g.pixels(dc).unwrap().iter().all(|pixel| *pixel == 0));
    g.end_path(dc).unwrap();
    let (points, flags) = g.path_points(dc).unwrap();
    assert_eq!(points.len(), 2);
    assert_eq!(flags, [PT_MOVETO, PT_LINETO]);
    assert_eq!(points[1], Point { x: 8, y: 1 });
}

#[test]
fn a_rectangle_drawn_while_a_path_is_open_records_one_closed_figure() {
    let (mut g, dc) = setup();
    let brush = g.create_solid_brush(0x0000_00ff).unwrap();
    g.select_brush(dc, brush).unwrap();
    g.begin_path(dc).unwrap();
    g.pen_rectangle(dc, Rect { left: 1, top: 1, right: 5, bottom: 5 }, None).unwrap();
    assert!(g.pixels(dc).unwrap().iter().all(|pixel| *pixel == 0));
    g.end_path(dc).unwrap();
    assert_eq!(g.path_points(dc).map(|(points, _)| points.len()), Ok(4));
}

#[test]
fn the_same_calls_rasterize_once_the_path_is_closed() {
    let (mut g, dc) = setup();
    let brush = g.create_solid_brush(0x0000_00ff).unwrap();
    g.select_brush(dc, brush).unwrap();
    g.pen_rectangle(dc, Rect { left: 1, top: 1, right: 5, bottom: 5 }, None).unwrap();
    assert!(g.pixels(dc).unwrap().iter().any(|pixel| *pixel != 0));
}
