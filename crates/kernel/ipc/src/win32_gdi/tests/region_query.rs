use super::*;
use crate::win32_gdi::Rect;
use crate::win32_window::{PaintRegion, WindowRect};

fn r(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }
fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect { Rect { left, top, right, bottom } }

#[test]
fn membership_excludes_the_right_and_bottom_edges() {
    let region = PaintRegion::from_rect(r(2, 3, 6, 7)).unwrap();
    assert!(pt_in_region(&region, 2, 3));
    assert!(pt_in_region(&region, 5, 6));
    assert!(!pt_in_region(&region, 6, 6));
    assert!(!pt_in_region(&region, 5, 7));
    assert!(!pt_in_region(&region, 1, 3));
}

#[test]
fn a_hole_is_not_covered_even_inside_the_bounding_box() {
    let mut region = PaintRegion::from_rect(r(0, 0, 6, 6)).unwrap();
    region.subtract(&PaintRegion::from_rect(r(2, 2, 4, 4)).unwrap()).unwrap();
    assert!(!pt_in_region(&region, 3, 3));
    assert!(pt_in_region(&region, 1, 3));
    assert!(!rect_in_region(&region, rect(2, 2, 4, 4)));
    assert!(rect_in_region(&region, rect(2, 2, 5, 4)));
}

#[test]
fn rectangle_overlap_is_partial_not_containment_and_normalizes_reversed_input() {
    let region = PaintRegion::from_rect(r(0, 0, 4, 4)).unwrap();
    assert!(rect_in_region(&region, rect(3, 3, 20, 20)));
    assert!(rect_in_region(&region, rect(20, 20, 3, 3)));
    assert!(!rect_in_region(&region, rect(4, 0, 8, 4)));
    // A degenerate rectangle still reports the coverage of its own corner.
    assert!(rect_in_region(&region, rect(2, 2, 2, 2)));
    assert!(!rect_in_region(&region, rect(9, 9, 9, 9)));
}

#[test]
fn equality_compares_coverage_not_storage() {
    let one = PaintRegion::from_rect(r(0, 0, 4, 6)).unwrap();
    let split = PaintRegion::from_rects(&[r(0, 0, 4, 2), r(0, 2, 4, 6)]).unwrap();
    assert_eq!(equal_region(&one, &split), Ok(true));
    assert_eq!(equal_region(&one, &PaintRegion::from_rect(r(0, 0, 4, 5)).unwrap()), Ok(false));
    assert_eq!(equal_region(&PaintRegion::default(), &PaintRegion::default()), Ok(true));
    assert_eq!(equal_region(&one, &PaintRegion::default()), Ok(false));
}

#[test]
fn offsetting_moves_every_rectangle_and_refuses_an_overflowing_shift() {
    let region = PaintRegion::from_rect(r(1, 1, 2, 2)).unwrap();
    assert_eq!(offset_region(&region, 5, -1).unwrap().rects(), [r(6, 0, 7, 1)]);
    assert_eq!(offset_region(&region, i32::MAX, 0), Err(GdiError::HandleLimit));
}

#[test]
fn a_frame_is_the_border_ring_of_the_region() {
    let region = PaintRegion::from_rect(r(0, 0, 10, 10)).unwrap();
    let frame = frame_region(&region, 1, 1).unwrap();
    assert!(pt_in_region(&frame, 0, 0));
    assert!(pt_in_region(&frame, 9, 9));
    assert!(!pt_in_region(&frame, 1, 1));
    assert!(!pt_in_region(&frame, 5, 5));
    assert_eq!(frame_region(&PaintRegion::default(), 1, 1), Err(GdiError::NoSuchObject));
}

#[test]
fn a_frame_wider_than_the_region_covers_all_of_it() {
    let region = PaintRegion::from_rect(r(0, 0, 4, 4)).unwrap();
    assert_eq!(equal_region(&frame_region(&region, 9, 9).unwrap(), &region), Ok(true));
}

#[test]
fn region_data_round_trips_through_its_serialized_form() {
    let mut region = PaintRegion::from_rect(r(0, 0, 6, 6)).unwrap();
    region.subtract(&PaintRegion::from_rect(r(2, 2, 4, 4)).unwrap()).unwrap();
    let bytes = region_data_bytes(&region).unwrap();
    assert_eq!(bytes.len(), region_data_size(&bands::canonical(&region).unwrap()));
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), RGNDATAHEADER_BYTES as u32);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), RDH_RECTANGLES);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 4);
    assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 4 * 16);
    assert_eq!(i32::from_le_bytes(bytes[16..20].try_into().unwrap()), 0);
    assert_eq!(i32::from_le_bytes(bytes[24..28].try_into().unwrap()), 6);
    assert_eq!(equal_region(&region_from_data(&bytes).unwrap(), &region), Ok(true));
}

#[test]
fn a_short_or_undersized_region_data_image_is_refused() {
    assert_eq!(region_from_data(&[0u8; 8]), Err(GdiError::InvalidDimensions));
    let mut bytes = [0u8; RGNDATAHEADER_BYTES];
    bytes[0] = 16;
    assert_eq!(region_from_data(&bytes), Err(GdiError::InvalidDimensions));
    let mut bytes = [0u8; RGNDATAHEADER_BYTES];
    bytes[0] = RGNDATAHEADER_BYTES as u8; bytes[8] = 2;
    assert_eq!(region_from_data(&bytes), Err(GdiError::InvalidDimensions));
}

#[test]
fn degenerate_rectangles_in_region_data_contribute_no_coverage() {
    let mut bytes = alloc::vec::Vec::new();
    for word in [RGNDATAHEADER_BYTES as u32, RDH_RECTANGLES, 2, 32] { bytes.extend_from_slice(&word.to_le_bytes()); }
    for value in [0i32, 0, 4, 4] { bytes.extend_from_slice(&value.to_le_bytes()); }
    for value in [5i32, 5, 5, 9] { bytes.extend_from_slice(&value.to_le_bytes()); }
    for value in [0i32, 0, 4, 4] { bytes.extend_from_slice(&value.to_le_bytes()); }
    let region = region_from_data(&bytes).unwrap();
    assert_eq!(bands::canonical(&region).unwrap(), [r(0, 0, 4, 4)]);
}
