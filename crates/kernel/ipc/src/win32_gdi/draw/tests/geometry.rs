use super::*;
use crate::win32_gdi::{AD_CLOCKWISE, AD_COUNTERCLOCKWISE};

#[test]
fn an_empty_extent_produces_no_quadrant_points() {
    assert!(ellipse_first_quadrant(0, 10).unwrap().is_empty());
    assert!(ellipse_first_quadrant(10, 0).unwrap().is_empty());
    assert!(ellipse_first_quadrant(-4, -4).unwrap().is_empty());
}

#[test]
fn the_quadrant_run_starts_on_the_x_axis_and_ends_at_the_midpoint() {
    let points = ellipse_first_quadrant(11, 11).unwrap();
    assert_eq!(points[0], Point { x: 10, y: 5 });
    let last = *points.last().unwrap();
    assert_eq!(last.x, 5, "the run stops when it reaches the horizontal midpoint");
    assert!(last.y > points[0].y, "the run climbs away from the x axis");
    // Every step moves at most one pixel on each axis.
    for pair in points.windows(2) {
        assert!((pair[0].x - pair[1].x).abs() <= 1 && (pair[0].y - pair[1].y).abs() <= 1);
    }
}

#[test]
fn the_quadrant_run_stays_on_the_ellipse_it_describes() {
    let (width, height) = (21, 13);
    let points = ellipse_first_quadrant(width, height).unwrap();
    let (a, b) = ((width - 1) as f64 / 2.0, (height - 1) as f64 / 2.0);
    for point in &points {
        let (x, y) = (f64::from(point.x) - a, f64::from(point.y) - (height / 2) as f64);
        let radius = x * x / (a * a) + y * y / (b * b);
        assert!(radius > 0.6 && radius < 1.5, "point {point:?} sits at {radius}");
    }
}

#[test]
fn a_full_sweep_walks_the_whole_ellipse_in_the_requested_direction() {
    let rect = Rect { left: 0, top: 0, right: 20, bottom: 20 };
    let start = Point { x: 10, y: 0 };
    let clockwise = arc_points(AD_CLOCKWISE, rect, start, start).unwrap();
    let counter = arc_points(AD_COUNTERCLOCKWISE, rect, start, start).unwrap();
    assert_eq!(clockwise.len(), counter.len());
    assert!(clockwise.len() >= 4 * ellipse_first_quadrant(20, 20).unwrap().len() - 1);
    // Both runs cover the same set of pixels, traversed the other way round.
    let mut a = clockwise.clone(); a.sort_by_key(|p| (p.x, p.y));
    let mut b = counter.clone(); b.sort_by_key(|p| (p.x, p.y));
    assert_eq!(a, b);
    assert_ne!(clockwise[1], counter[1]);
}

#[test]
fn an_arc_stays_inside_the_rectangle_that_bounds_its_ellipse() {
    let rect = Rect { left: 4, top: 6, right: 24, bottom: 18 };
    let points = arc_points(AD_COUNTERCLOCKWISE, rect, Point { x: 10, y: 0 }, Point { x: -10, y: 0 }).unwrap();
    assert!(!points.is_empty());
    for point in &points {
        assert!(point.x >= rect.left && point.x < rect.right, "{point:?}");
        assert!(point.y >= rect.top && point.y < rect.bottom, "{point:?}");
    }
}

#[test]
fn an_empty_ellipse_extent_produces_no_arc() {
    let rect = Rect { left: 5, top: 5, right: 5, bottom: 9 };
    assert!(arc_points(AD_CLOCKWISE, rect, Point { x: 1, y: 0 }, Point { x: 0, y: 1 }).unwrap().is_empty());
}

#[test]
fn the_rounded_rectangle_outline_is_symmetric_about_both_axes() {
    let rect = Rect { left: 0, top: 0, right: 20, bottom: 16 };
    let points = round_rect_points(rect, 8, 6, AD_COUNTERCLOCKWISE).unwrap();
    assert!(points.len() >= 8);
    for point in &points {
        assert!(point.x >= rect.left && point.x < rect.right, "{point:?}");
        assert!(point.y >= rect.top && point.y < rect.bottom, "{point:?}");
        let mirrored_x = Point { x: rect.left + rect.right - 1 - point.x, y: point.y };
        let mirrored_y = Point { x: point.x, y: rect.top + rect.bottom - 1 - point.y };
        assert!(points.contains(&mirrored_x), "no horizontal mirror of {point:?}");
        assert!(points.contains(&mirrored_y), "no vertical mirror of {point:?}");
    }
}

#[test]
fn a_corner_ellipse_that_spans_an_odd_side_drops_the_midpoint_each_mirror_shares() {
    let rect = Rect { left: 0, top: 0, right: 11, bottom: 11 };
    let quadrant = ellipse_first_quadrant(11, 11).unwrap().len();
    let spanning = round_rect_points(rect, 11, 11, AD_COUNTERCLOCKWISE).unwrap();
    // Each mirror doubles the run and drops the one point the two halves share.
    assert_eq!(spanning.len(), 4 * quadrant - 3);
    // A corner ellipse smaller than the side shares no midpoint, so nothing drops.
    let corner = round_rect_points(rect, 5, 5, AD_COUNTERCLOCKWISE).unwrap();
    assert_eq!(corner.len(), 4 * ellipse_first_quadrant(5, 5).unwrap().len());
}
