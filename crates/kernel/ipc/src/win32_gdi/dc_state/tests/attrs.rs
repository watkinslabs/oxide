use super::*;
use crate::win32_gdi::{DeviceGeometry, Size, Point, Xform, LAYOUT_RTL, MM_ANISOTROPIC, MM_TEXT,
    XFORM_WORLD_TO_DEVICE, LP_TO_DP, DEFAULT_MITER_LIMIT};

const DEVICE: DeviceGeometry = DeviceGeometry { res: Size { cx: 800, cy: 600 }, size: Size { cx: 211, cy: 158 } };

fn context() -> (GdiManager, u32) {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(80, 60).unwrap();
    (gdi, dc)
}

#[test]
fn the_layout_call_reports_the_previous_value_and_forces_anisotropic_mapping() {
    let (mut gdi, dc) = context();
    assert_eq!(gdi.dc_attr(dc).unwrap().map_mode, MM_TEXT);
    assert_eq!(gdi.set_layout(dc, LAYOUT_RTL), Ok(0));
    assert_eq!(gdi.dc_attr(dc).unwrap().map_mode, MM_ANISOTROPIC);
    assert_eq!(gdi.set_layout(dc, 0), Ok(LAYOUT_RTL));
    assert_eq!(gdi.set_layout(99, 0), Err(GdiError::NoSuchObject));
}

#[test]
fn the_miter_limit_round_trips_through_its_raw_bit_pattern() {
    let (mut gdi, dc) = context();
    assert_eq!(gdi.miter_limit(dc), Ok(DEFAULT_MITER_LIMIT));
    assert_eq!(gdi.set_miter_limit(dc, 2.5f32.to_bits()), Ok(DEFAULT_MITER_LIMIT));
    assert_eq!(gdi.miter_limit(dc), Ok(2.5));
    assert_eq!(gdi.miter_limit(99), Err(GdiError::NoSuchObject));
}

#[test]
fn an_unknown_transform_space_is_refused() {
    let (gdi, dc) = context();
    assert_eq!(gdi.dc_transform(dc, XFORM_WORLD_TO_DEVICE), Ok(Xform::IDENTITY));
    assert_eq!(gdi.dc_transform(dc, 0x111), Err(GdiError::InvalidDimensions));
}

#[test]
fn scaling_reports_the_previous_extent_on_success_and_on_refusal() {
    let (mut gdi, dc) = context();
    gdi.dc_attr_mut_for_test(dc).map_mode = MM_ANISOTROPIC;
    gdi.dc_attr_mut_for_test(dc).vport_ext = Size { cx: 6, cy: 8 };
    assert_eq!(gdi.scale_viewport_ext(dc, [2, 1, 1, 2], DEVICE), Ok(Size { cx: 6, cy: 8 }));
    assert_eq!(gdi.dc_attr(dc).unwrap().vport_ext, Size { cx: 12, cy: 4 });
    assert_eq!(gdi.scale_viewport_ext(dc, [1, 0, 1, 1], DEVICE),
        Err((Size { cx: 12, cy: 4 }, GdiError::InvalidDimensions)));
    assert_eq!(gdi.scale_window_ext(99, [1, 1, 1, 1], DEVICE), Err((Size::default(), GdiError::NoSuchObject)));
}

#[test]
fn a_virtual_resolution_needs_all_four_terms_together() {
    let (mut gdi, dc) = context();
    assert_eq!(gdi.set_virtual_resolution(dc, Size { cx: 10, cy: 10 }, Size { cx: 5, cy: 0 }),
        Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.set_virtual_resolution(dc, Size { cx: 10, cy: 10 }, Size { cx: 5, cy: 5 }), Ok(()));
    assert_eq!(gdi.dc_attr(dc).unwrap().effective_res(DEVICE), Size { cx: 10, cy: 10 });
}

#[test]
fn point_transformation_runs_through_the_context_transform() {
    let (mut gdi, dc) = context();
    gdi.dc_attr_mut_for_test(dc).vport_ext = Size { cx: 3, cy: 3 };
    gdi.compute_xform_coefficients(dc, DEVICE).unwrap();
    let mut points = [Point { x: 2, y: 4 }];
    assert_eq!(gdi.transform_points(dc, LP_TO_DP, &mut points), Ok(()));
    assert_eq!(points, [Point { x: 6, y: 12 }]);
    assert_eq!(gdi.transform_points(dc, 42, &mut points), Err(GdiError::InvalidDimensions));
}

#[test]
fn the_first_pixel_format_claim_wins_and_a_conflicting_claim_is_refused() {
    let (mut gdi, dc) = context();
    assert_eq!(gdi.set_pixel_format(dc, 3), Ok(true));
    assert_eq!(gdi.set_pixel_format(dc, 3), Ok(true));
    assert_eq!(gdi.set_pixel_format(dc, 4), Ok(false));
    assert_eq!(gdi.dc_attr(dc).unwrap().pixel_format, 3);
    assert_eq!(gdi.set_pixel_format(99, 1), Err(GdiError::NoSuchObject));
}

#[test]
fn the_bounds_calls_reach_the_accumulator_through_the_object_owner() {
    let (mut gdi, dc) = context();
    assert_eq!(gdi.set_bounds_rect(dc, None, 0x0004), Ok(0x0008 | 0x0001));
    assert_eq!(gdi.set_bounds_rect(dc, Some(Rect { left: 1, top: 1, right: 5, bottom: 5 }), 0x0002), Ok(0x0004 | 0x0001));
    assert_eq!(gdi.get_bounds_rect(dc, true, 0x0001),
        Ok((0x0003, Some(Rect { left: 1, top: 1, right: 5, bottom: 5 }))));
    assert_eq!(gdi.get_bounds_rect(99, true, 0), Err(GdiError::NoSuchObject));
}

#[test]
fn a_metafile_context_records_rather_than_rasterises_and_owns_no_surface() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_metafile_dc().unwrap();
    assert_eq!(gdi.dc_attr(dc).unwrap().kind, crate::win32_gdi::DcKind::EnhMetafile);
    assert_eq!(gdi.pixels(dc), Some(&[][..]));
    assert_eq!(gdi.dc_attr(dc).unwrap().vis_rect, Rect { left: 0, top: 0, right: 0, bottom: 0 });
    // It is a real object, so the object owner deletes it like any other.
    assert_eq!(gdi.delete_object(dc), Ok(()));
    assert_eq!(gdi.dc_attr(dc), Err(GdiError::NoSuchObject));
}

#[test]
fn a_window_context_is_a_display_context_and_a_created_one_is_a_memory_context() {
    let mut gdi = GdiManager::new();
    let window = gdi.acquire_window_dc(5, 8, 8).unwrap();
    let memory = gdi.create_dc(8, 8).unwrap();
    assert_eq!(gdi.dc_attr(window).unwrap().kind, crate::win32_gdi::DcKind::Display);
    assert_eq!(gdi.dc_attr(memory).unwrap().kind, crate::win32_gdi::DcKind::Memory);
}
