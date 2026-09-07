use super::*;

#[test]
fn a_run_that_is_not_three_n_plus_one_has_no_curve_to_flatten() {
    for count in [0usize, 1, 2, 3, 5, 6] {
        let points: alloc::vec::Vec<Point> = (0..count).map(|i| Point { x: i as i32, y: 0 }).collect();
        assert_eq!(flatten_bezier(&points), Err(GdiError::InvalidDimensions), "count {count}");
    }
}

#[test]
fn a_straight_control_polygon_flattens_to_its_own_endpoints() {
    let points = [Point { x: 0, y: 0 }, Point { x: 10, y: 0 }, Point { x: 20, y: 0 }, Point { x: 30, y: 0 }];
    assert_eq!(flatten_bezier(&points).unwrap(), [Point { x: 0, y: 0 }, Point { x: 30, y: 0 }]);
}

#[test]
fn a_curved_control_polygon_is_subdivided_and_keeps_both_endpoints() {
    let points = [Point { x: 0, y: 0 }, Point { x: 0, y: 100 }, Point { x: 100, y: 100 }, Point { x: 100, y: 0 }];
    let flat = flatten_bezier(&points).unwrap();
    assert!(flat.len() > 2, "a curve must produce more than one segment");
    assert_eq!(flat[0], Point { x: 0, y: 0 });
    assert_eq!(*flat.last().unwrap(), Point { x: 100, y: 0 });
    // The curve stays inside the control polygon's bounding box.
    for point in &flat {
        assert!((0..=100).contains(&point.x) && (0..=100).contains(&point.y), "{point:?}");
    }
    // It is monotone in x, as this control polygon requires.
    for pair in flat.windows(2) { assert!(pair[1].x >= pair[0].x); }
}

#[test]
fn consecutive_curves_join_without_repeating_the_shared_point() {
    let points = [Point { x: 0, y: 0 }, Point { x: 0, y: 50 }, Point { x: 50, y: 50 }, Point { x: 50, y: 0 },
                  Point { x: 50, y: -50 }, Point { x: 100, y: -50 }, Point { x: 100, y: 0 }];
    let flat = flatten_bezier(&points).unwrap();
    assert_eq!(flat[0], Point { x: 0, y: 0 });
    assert_eq!(*flat.last().unwrap(), Point { x: 100, y: 0 });
    assert_eq!(flat.iter().filter(|p| **p == Point { x: 50, y: 0 }).count(), 1);
}
