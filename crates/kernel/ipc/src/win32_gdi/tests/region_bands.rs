use super::*;
use crate::win32_window::{PaintRegion, WindowRect};

fn r(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }

#[test]
fn one_rectangle_is_one_band() {
    let region = PaintRegion::from_rect(r(1, 2, 5, 9)).unwrap();
    assert_eq!(canonical(&region).unwrap(), [r(1, 2, 5, 9)]);
    assert_eq!(extents(&canonical(&region).unwrap()), Some(r(1, 2, 5, 9)));
}

#[test]
fn vertically_stacked_rectangles_coalesce_into_one_band() {
    let region = PaintRegion::from_rects(&[r(0, 0, 4, 2), r(0, 2, 4, 5)]).unwrap();
    assert_eq!(canonical(&region).unwrap(), [r(0, 0, 4, 5)]);
}

#[test]
fn horizontally_touching_rectangles_merge_within_a_band() {
    let region = PaintRegion::from_rects(&[r(0, 0, 2, 3), r(2, 0, 7, 3)]).unwrap();
    assert_eq!(canonical(&region).unwrap(), [r(0, 0, 7, 3)]);
}

#[test]
fn storage_order_does_not_change_canonical_form() {
    let first = PaintRegion::from_rects(&[r(0, 0, 3, 1), r(5, 0, 8, 1), r(0, 1, 8, 4)]).unwrap();
    let second = PaintRegion::from_rects(&[r(0, 1, 8, 4), r(5, 0, 8, 1), r(0, 0, 3, 1)]).unwrap();
    assert_eq!(canonical(&first).unwrap(), canonical(&second).unwrap());
    assert_eq!(canonical(&first).unwrap(), [r(0, 0, 3, 1), r(5, 0, 8, 1), r(0, 1, 8, 4)]);
}

#[test]
fn a_gap_between_bands_prevents_vertical_coalescing() {
    let region = PaintRegion::from_rects(&[r(0, 0, 4, 2), r(0, 5, 4, 7)]).unwrap();
    assert_eq!(canonical(&region).unwrap(), [r(0, 0, 4, 2), r(0, 5, 4, 7)]);
}

#[test]
fn empty_coverage_has_no_bands_and_no_extent() {
    let region = PaintRegion::default();
    assert!(canonical(&region).unwrap().is_empty());
    assert_eq!(extents(&canonical(&region).unwrap()), None);
}

#[test]
fn a_ring_keeps_the_hole_as_two_rectangles_in_the_middle_band() {
    let mut region = PaintRegion::from_rect(r(0, 0, 6, 6)).unwrap();
    region.subtract(&PaintRegion::from_rect(r(2, 2, 4, 4)).unwrap()).unwrap();
    assert_eq!(canonical(&region).unwrap(),
        [r(0, 0, 6, 2), r(0, 2, 2, 4), r(4, 2, 6, 4), r(0, 4, 6, 6)]);
}
