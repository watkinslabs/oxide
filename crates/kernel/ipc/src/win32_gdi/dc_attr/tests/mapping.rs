use super::*;
use crate::win32_gdi::{Point, Xform};
use super::super::{LAYOUT_RTL, DP_TO_LP};

const DEVICE: DeviceGeometry = DeviceGeometry { res: Size { cx: 1024, cy: 768 }, size: Size { cx: 270, cy: 203 } };

#[test]
fn text_mapping_is_the_identity_page_transform() {
    let mut attr = DcAttr::new();
    attr.set_vis_rect(1024, 768);
    assert!(attr.set_map_mode(MM_TEXT, DEVICE));
    assert_eq!(attr.window_to_viewport(), Xform::IDENTITY);
    assert_eq!(attr.lp_to_dp(Point { x: 7, y: 9 }), Point { x: 7, y: 9 });
}

#[test]
fn metric_modes_derive_their_extents_from_the_device_geometry() {
    let mut attr = DcAttr::new();
    assert!(attr.set_map_mode(MM_LOMETRIC, DEVICE));
    assert_eq!(attr.wnd_ext, Size { cx: 2700, cy: 2030 });
    assert_eq!(attr.vport_ext, Size { cx: 1024, cy: -768 });
    assert!(attr.set_map_mode(MM_HIMETRIC, DEVICE));
    assert_eq!(attr.wnd_ext, Size { cx: 27000, cy: 20300 });
    assert!(attr.set_map_mode(MM_TWIPS, DEVICE));
    assert_eq!(attr.wnd_ext, Size { cx: muldiv(14400, 270, 254), cy: muldiv(14400, 203, 254) });
    assert!(attr.set_map_mode(MM_LOENGLISH, DEVICE));
    assert_eq!(attr.wnd_ext, Size { cx: muldiv(1000, 270, 254), cy: muldiv(1000, 203, 254) });
    assert!(attr.set_map_mode(MM_HIENGLISH, DEVICE));
    assert_eq!(attr.wnd_ext, Size { cx: muldiv(10000, 270, 254), cy: muldiv(10000, 203, 254) });
}

#[test]
fn an_unknown_mapping_mode_is_refused_and_changes_nothing() {
    let mut attr = DcAttr::new();
    assert!(attr.set_map_mode(MM_LOMETRIC, DEVICE));
    let before = attr;
    assert!(!attr.set_map_mode(99, DEVICE));
    assert_eq!(attr, before);
}

#[test]
fn a_virtual_resolution_override_replaces_the_device_geometry() {
    let mut attr = DcAttr::new();
    assert!(attr.set_virtual_resolution(Size { cx: 100, cy: 50 }, Size { cx: 20, cy: 10 }));
    assert_eq!(attr.effective_res(DEVICE), Size { cx: 100, cy: 50 });
    assert_eq!(attr.effective_size(DEVICE), Size { cx: 20, cy: 10 });
    assert!(attr.set_map_mode(MM_LOMETRIC, DEVICE));
    assert_eq!(attr.wnd_ext, Size { cx: 200, cy: 100 });
    assert_eq!(attr.vport_ext, Size { cx: 100, cy: -50 });
    // Restoring the device's own geometry needs all four terms zeroed.
    assert!(attr.set_virtual_resolution(Size { cx: 0, cy: 0 }, Size { cx: 0, cy: 0 }));
    assert_eq!(attr.effective_res(DEVICE), DEVICE.res);
}

#[test]
fn a_partially_zero_virtual_resolution_is_refused() {
    let mut attr = DcAttr::new();
    assert!(!attr.set_virtual_resolution(Size { cx: 100, cy: 0 }, Size { cx: 20, cy: 10 }));
    assert_eq!(attr.virtual_res, Size { cx: 0, cy: 0 });
}

#[test]
fn scaling_only_applies_in_the_two_scalable_modes_and_reports_the_previous_extent() {
    let mut attr = DcAttr::new();
    // MM_TEXT ignores the scale but still succeeds and reports the extent.
    assert_eq!(attr.scale_viewport_ext([2, 1, 2, 1], DEVICE), Ok(Size { cx: 1, cy: 1 }));
    assert_eq!(attr.vport_ext, Size { cx: 1, cy: 1 });
    attr.set_map_mode(MM_ANISOTROPIC, DEVICE);
    attr.vport_ext = Size { cx: 10, cy: 20 };
    assert_eq!(attr.scale_viewport_ext([3, 2, 1, 4], DEVICE), Ok(Size { cx: 10, cy: 20 }));
    assert_eq!(attr.vport_ext, Size { cx: 15, cy: 5 });
    // A quotient that truncates to zero is floored at one.
    attr.vport_ext = Size { cx: 1, cy: 1 };
    assert_eq!(attr.scale_viewport_ext([1, 4, 1, 4], DEVICE), Ok(Size { cx: 1, cy: 1 }));
    assert_eq!(attr.vport_ext, Size { cx: 1, cy: 1 });
}

#[test]
fn a_zero_scaling_term_fails_only_where_scaling_applies() {
    let mut attr = DcAttr::new();
    assert_eq!(attr.scale_window_ext([0, 1, 1, 1], DEVICE), Ok(Size { cx: 1, cy: 1 }));
    attr.set_map_mode(MM_ANISOTROPIC, DEVICE);
    attr.wnd_ext = Size { cx: 8, cy: 9 };
    assert_eq!(attr.scale_window_ext([1, 0, 1, 1], DEVICE), Err(Size { cx: 8, cy: 9 }));
    assert_eq!(attr.wnd_ext, Size { cx: 8, cy: 9 });
}

#[test]
fn isotropic_correction_equalises_the_physical_unit_on_both_axes() {
    let mut attr = DcAttr::new();
    assert!(attr.set_map_mode(MM_ISOTROPIC, DEVICE));
    attr.wnd_ext = Size { cx: 1000, cy: 1000 };
    attr.vport_ext = Size { cx: 1000, cy: 1000 };
    attr.compute_xform_coefficients(DEVICE);
    // The wider physical axis is the one that shrinks.
    assert!(attr.vport_ext.cx < 1000 || attr.vport_ext.cy < 1000);
    assert!(attr.vport_ext.cx == 1000 || attr.vport_ext.cy == 1000);
}

#[test]
fn right_to_left_layout_mirrors_the_page_transform_about_the_visible_rectangle() {
    let mut attr = DcAttr::new();
    attr.set_vis_rect(100, 50);
    attr.layout = LAYOUT_RTL;
    attr.update_xforms();
    let page = attr.window_to_viewport();
    assert_eq!(page.m11, -1.0);
    assert_eq!(page.dx, 99.0);
    assert_eq!(attr.lp_to_dp(Point { x: 0, y: 0 }), Point { x: 99, y: 0 });
    assert_eq!(attr.lp_to_dp(Point { x: 99, y: 0 }), Point { x: 0, y: 0 });
}

#[test]
fn a_right_to_left_context_never_leaves_the_anisotropic_mode() {
    let mut attr = DcAttr::new();
    attr.layout = LAYOUT_RTL;
    attr.map_mode = MM_ANISOTROPIC;
    assert!(attr.set_map_mode(MM_LOMETRIC, DEVICE));
    assert_eq!(attr.map_mode, MM_ANISOTROPIC);
}

#[test]
fn a_degenerate_page_transform_marks_the_inverse_unavailable() {
    let mut attr = DcAttr::new();
    attr.vport_ext = Size { cx: 0, cy: 1 };
    attr.update_xforms();
    assert!(!attr.vport_to_world_valid);
    assert!(!attr.transform_points(DP_TO_LP, &mut [Point { x: 1, y: 1 }]));
}
