use super::*;
use crate::win32_gdi::{Point, Xform, Size};
use super::super::GM_ADVANCED;

#[test]
fn identity_mode_resets_the_world_transform_without_a_matrix() {
    let mut attr = DcAttr::new();
    attr.world_to_wnd = Xform { m11: 3.0, m12: 0.0, m21: 0.0, m22: 3.0, dx: 1.0, dy: 2.0 };
    assert!(attr.modify_world_transform(None, MWT_IDENTITY));
    assert_eq!(attr.world_to_wnd, Xform::IDENTITY);
}

#[test]
fn every_other_mode_requires_a_matrix() {
    let mut attr = DcAttr::new();
    for mode in [MWT_LEFTMULTIPLY, MWT_RIGHTMULTIPLY, MWT_SET] {
        assert!(!attr.modify_world_transform(None, mode), "mode {mode} must refuse a null matrix");
    }
    assert!(!attr.modify_world_transform(Some(Xform::IDENTITY), 99));
}

#[test]
fn left_and_right_multiplication_differ_in_operand_order() {
    let scale = Xform { m11: 2.0, m12: 0.0, m21: 0.0, m22: 2.0, dx: 0.0, dy: 0.0 };
    let translate = Xform { m11: 1.0, m12: 0.0, m21: 0.0, m22: 1.0, dx: 5.0, dy: 0.0 };
    let mut left = DcAttr::new();
    left.world_to_wnd = translate;
    assert!(left.modify_world_transform(Some(scale), MWT_LEFTMULTIPLY));
    assert_eq!(left.world_to_wnd.dx, 5.0);
    let mut right = DcAttr::new();
    right.world_to_wnd = translate;
    assert!(right.modify_world_transform(Some(scale), MWT_RIGHTMULTIPLY));
    assert_eq!(right.world_to_wnd.dx, 10.0);
}

#[test]
fn setting_the_transform_outright_needs_advanced_mode_and_a_non_singular_matrix() {
    let scale = Xform { m11: 2.0, m12: 0.0, m21: 0.0, m22: 2.0, dx: 0.0, dy: 0.0 };
    let mut attr = DcAttr::new();
    assert!(!attr.modify_world_transform(Some(scale), MWT_SET));
    assert_eq!(attr.world_to_wnd, Xform::IDENTITY);
    attr.graphics_mode = GM_ADVANCED;
    assert!(attr.modify_world_transform(Some(scale), MWT_SET));
    assert_eq!(attr.world_to_wnd, scale);
    let singular = Xform { m11: 1.0, m12: 2.0, m21: 2.0, m22: 4.0, dx: 0.0, dy: 0.0 };
    assert!(!attr.modify_world_transform(Some(singular), MWT_SET));
    assert_eq!(attr.world_to_wnd, scale);
}

#[test]
fn the_four_coordinate_spaces_report_distinct_transforms() {
    let mut attr = DcAttr::new();
    attr.graphics_mode = GM_ADVANCED;
    attr.vport_ext = Size { cx: 2, cy: 2 };
    attr.modify_world_transform(Some(Xform { m11: 3.0, m12: 0.0, m21: 0.0, m22: 3.0, dx: 0.0, dy: 0.0 }), MWT_SET);
    assert_eq!(attr.get_transform(XFORM_WORLD_TO_PAGE).unwrap().m11, 3.0);
    assert_eq!(attr.get_transform(XFORM_PAGE_TO_DEVICE).unwrap().m11, 2.0);
    assert_eq!(attr.get_transform(XFORM_WORLD_TO_DEVICE).unwrap().m11, 6.0);
    assert_eq!(attr.get_transform(XFORM_DEVICE_TO_WORLD).unwrap().m11, 1.0 / 6.0);
    assert_eq!(attr.get_transform(0x999), None);
}

#[test]
fn point_transformation_round_trips_through_both_directions() {
    let mut attr = DcAttr::new();
    attr.vport_ext = Size { cx: 4, cy: 4 };
    attr.update_xforms();
    let mut points = [Point { x: 3, y: 5 }, Point { x: -2, y: 0 }];
    assert!(attr.transform_points(LP_TO_DP, &mut points));
    assert_eq!(points, [Point { x: 12, y: 20 }, Point { x: -8, y: 0 }]);
    assert!(attr.transform_points(DP_TO_LP, &mut points));
    assert_eq!(points, [Point { x: 3, y: 5 }, Point { x: -2, y: 0 }]);
    assert!(!attr.transform_points(7, &mut points));
}
