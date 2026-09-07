use super::*;
use crate::win32_gdi::region::{bands, query};
use crate::win32_window::WindowRect;

fn p(x: i32, y: i32) -> Point { Point { x, y } }
fn r(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }

#[test]
fn an_axis_aligned_quadrilateral_becomes_one_rectangle() {
    let square = [p(0, 0), p(8, 0), p(8, 5), p(0, 5)];
    let region = poly_polygon_region(&square, &[4], ALTERNATE).unwrap();
    assert_eq!(region.rects(), [r(0, 0, 8, 5)]);
}

#[test]
fn a_closed_five_point_rectangle_is_recognized_as_a_rectangle() {
    let closed = [p(2, 1), p(2, 6), p(9, 6), p(9, 1), p(2, 1)];
    assert_eq!(poly_polygon_region(&closed, &[5], ALTERNATE).unwrap().rects(), [r(2, 1, 9, 6)]);
}

#[test]
fn a_triangle_covers_the_expected_scanline_spans() {
    let triangle = [p(0, 0), p(8, 0), p(0, 8)];
    let region = poly_polygon_region(&triangle, &[3], ALTERNATE).unwrap();
    let bands = bands::canonical(&region).unwrap();
    assert_eq!(bands.first().map(|b| b.top), Some(0));
    assert_eq!(bands.last().map(|b| b.bottom), Some(8));
    // Row width shrinks monotonically from the top edge to the apex.
    let width = |y: i32| region.rects().iter().filter(|b| b.top <= y && b.bottom > y).map(|b| b.right - b.left).sum::<i32>();
    for y in 1..8 { assert!(width(y) <= width(y - 1), "row {y}"); }
    assert!(query::pt_in_region(&region, 0, 0));
    assert!(!query::pt_in_region(&region, 7, 7));
}

#[test]
fn alternate_parity_leaves_a_hole_where_winding_fills_it() {
    let outer = [p(0, 0), p(10, 0), p(10, 10), p(0, 10)];
    let inner = [p(3, 3), p(7, 3), p(7, 7), p(3, 7)];
    let mut points = alloc::vec::Vec::new();
    points.extend_from_slice(&outer); points.extend_from_slice(&inner);
    let alternate = poly_polygon_region(&points, &[4, 4], ALTERNATE).unwrap();
    let winding = poly_polygon_region(&points, &[4, 4], WINDING).unwrap();
    assert!(!query::pt_in_region(&alternate, 5, 5));
    assert!(query::pt_in_region(&winding, 5, 5));
    assert!(query::pt_in_region(&alternate, 1, 5));
}

#[test]
fn a_degenerate_polygon_has_no_coverage() {
    assert!(poly_polygon_region(&[p(0, 0), p(4, 0)], &[2], ALTERNATE).unwrap().is_empty());
    assert!(poly_polygon_region(&[p(0, 0)], &[1], ALTERNATE).unwrap().is_empty());
}

#[test]
fn a_point_count_past_the_supplied_array_is_refused() {
    assert_eq!(poly_polygon_region(&[p(0, 0), p(1, 1), p(2, 0)], &[3, 3], ALTERNATE), Err(GdiError::InvalidDimensions));
}

#[test]
fn an_unbounded_vertical_span_is_refused_rather_than_scanned() {
    let tall = [p(0, i32::MIN / 2), p(4, i32::MIN / 2), p(4, i32::MAX / 2), p(0, i32::MAX / 2), p(1, 0)];
    assert_eq!(poly_polygon_region(&tall, &[5], ALTERNATE), Err(GdiError::HandleLimit));
}
