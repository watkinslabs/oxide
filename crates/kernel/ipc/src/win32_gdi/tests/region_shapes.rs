use super::*;
use crate::win32_gdi::region::bands;
use crate::win32_window::WindowRect;

#[test]
fn small_corners_degenerate_to_the_interior_rectangle() {
    let rects = round_rect_rects(0, 0, 10, 10, 1, 1).unwrap();
    assert_eq!(rects, [WindowRect { left: 0, top: 0, right: 9, bottom: 9 }]);
}

#[test]
fn reversed_coordinates_are_ordered_before_the_interior_adjustment() {
    assert_eq!(round_rect_rects(10, 10, 0, 0, 0, 0).unwrap(), round_rect_rects(0, 0, 10, 10, 0, 0).unwrap());
}

#[test]
fn a_degenerate_rectangle_has_no_coverage() {
    assert!(round_rect_rects(3, 3, 4, 4, 0, 0).unwrap().is_empty());
}

#[test]
fn rounded_corners_produce_one_scanline_per_corner_row_and_one_tall_middle_span() {
    let rects = round_rect_rects(0, 0, 21, 21, 8, 8).unwrap();
    assert_eq!(rects.len(), 8);
    // Every corner row is a single scanline; the middle span carries the straight sides.
    for (index, rect) in rects.iter().enumerate() {
        if index == 4 { continue; }
        assert_eq!(rect.bottom - rect.top, 1);
    }
    assert_eq!(rects[4], WindowRect { left: 0, top: 4, right: 20, bottom: 17 });
    // Corner rows are inset symmetrically about the interior centre.
    assert_eq!(rects[0].left - 0, 20 - rects[0].right);
    assert!(rects[0].left > rects[1].left);
}

#[test]
fn an_ellipse_is_the_full_corner_rounded_rectangle() {
    let ellipse = elliptic_region(0, 0, 20, 12).unwrap();
    let round = round_rect_region(0, 0, 20, 12, 20, 12).unwrap();
    assert_eq!(bands::canonical(&ellipse).unwrap(), bands::canonical(&round).unwrap());
}

#[test]
fn an_ellipse_is_widest_at_its_vertical_centre_and_inset_at_the_top() {
    let region = elliptic_region(0, 0, 20, 12).unwrap();
    let width_at = |y: i32| region.rects().iter().filter(|r| r.top <= y && r.bottom > y)
        .map(|r| r.right - r.left).max().unwrap_or(0);
    assert!(width_at(5) > width_at(0));
    assert_eq!(width_at(0), width_at(10));
    assert_eq!(width_at(11), 0);
}

#[test]
fn ellipse_coverage_is_symmetric_about_both_axes() {
    let region = elliptic_region(0, 0, 21, 11).unwrap();
    let bands = bands::canonical(&region).unwrap();
    let bound = bands::extents(&bands).unwrap();
    for band in &bands {
        let mirrored = bands.iter().find(|other| other.top == bound.top + bound.bottom - band.bottom);
        assert_eq!(mirrored.map(|m| (m.left, m.right)), Some((band.left, band.right)));
        assert_eq!(band.left - bound.left, bound.right - band.right);
    }
}
