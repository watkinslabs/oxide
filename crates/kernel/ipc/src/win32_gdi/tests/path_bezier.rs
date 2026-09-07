use super::*;

fn p(x: i32, y: i32) -> Point { Point { x, y } }

#[test]
fn a_straight_control_polygon_flattens_to_its_endpoints() {
    let line = flatten(&[p(0, 0), p(10, 0), p(20, 0), p(30, 0)]).unwrap();
    assert_eq!(line, [p(0, 0), p(30, 0)]);
}

#[test]
fn a_curved_segment_produces_a_monotone_polyline_between_its_endpoints() {
    let curve = flatten(&[p(0, 0), p(0, 40), p(40, 40), p(40, 0)]).unwrap();
    assert!(curve.len() > 2);
    assert_eq!(curve.first(), Some(&p(0, 0)));
    assert_eq!(curve.last(), Some(&p(40, 0)));
    for pair in curve.windows(2) { assert!(pair[1].x >= pair[0].x); }
    // The curve stays inside the control hull.
    for point in &curve { assert!(point.y >= 0 && point.y <= 40 && point.x >= 0 && point.x <= 40); }
}

#[test]
fn consecutive_segments_share_one_joining_point() {
    let two = flatten(&[p(0, 0), p(0, 20), p(20, 20), p(20, 0), p(20, -20), p(40, -20), p(40, 0)]).unwrap();
    assert_eq!(two.iter().filter(|point| **point == p(20, 0)).count(), 1);
    assert_eq!(two.first(), Some(&p(0, 0)));
    assert_eq!(two.last(), Some(&p(40, 0)));
}

#[test]
fn a_point_count_that_is_not_three_n_plus_one_is_refused() {
    assert_eq!(flatten(&[]), Err(GdiError::InvalidDimensions));
    assert_eq!(flatten(&[p(0, 0), p(1, 1), p(2, 2)]), Err(GdiError::InvalidDimensions));
}
