use super::*;
use crate::win32_gdi::{DcKind, GM_ADVANCED, Xform, MWT_SET, Rect};

fn context() -> (GdiManager, u32) {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(64, 32).unwrap();
    (gdi, dc)
}

#[test]
fn each_save_reports_its_own_one_based_depth() {
    let (mut gdi, dc) = context();
    assert_eq!(gdi.save_dc(dc), Ok(1));
    assert_eq!(gdi.save_dc(dc), Ok(2));
    assert_eq!(gdi.save_dc(dc), Ok(3));
    assert_eq!(gdi.dc_attr(dc).unwrap().save_level, 3);
    assert_eq!(gdi.save_dc(99), Err(GdiError::NoSuchObject));
}

#[test]
fn restoring_a_level_discards_every_level_above_it() {
    let (mut gdi, dc) = context();
    gdi.save_dc(dc).unwrap();
    gdi.set_layout(dc, 1).unwrap();
    gdi.save_dc(dc).unwrap();
    gdi.set_layout(dc, 0).unwrap();
    gdi.save_dc(dc).unwrap();
    assert_eq!(gdi.restore_dc(dc, 2), Ok(()));
    // Level two saw the right-to-left layout; levels above it are gone.
    assert_eq!(gdi.dc_attr(dc).unwrap().layout, 1);
    assert_eq!(gdi.dc_attr(dc).unwrap().save_level, 1);
    assert_eq!(gdi.restore_dc(dc, 2), Err(GdiError::InvalidDimensions));
}

#[test]
fn a_negative_level_counts_back_from_the_current_depth() {
    let (mut gdi, dc) = context();
    gdi.set_miter_limit(dc, 2.0f32.to_bits()).unwrap();
    gdi.save_dc(dc).unwrap();
    gdi.set_miter_limit(dc, 3.0f32.to_bits()).unwrap();
    gdi.save_dc(dc).unwrap();
    gdi.set_miter_limit(dc, 4.0f32.to_bits()).unwrap();
    // -1 is the most recent level, which saw a limit of three.
    assert_eq!(gdi.restore_dc(dc, -1), Ok(()));
    assert_eq!(gdi.miter_limit(dc), Ok(3.0));
    assert_eq!(gdi.dc_attr(dc).unwrap().save_level, 1);
    assert_eq!(gdi.restore_dc(dc, -1), Ok(()));
    assert_eq!(gdi.miter_limit(dc), Ok(2.0));
}

#[test]
fn level_zero_and_an_out_of_range_level_are_refused_without_unwinding() {
    let (mut gdi, dc) = context();
    gdi.save_dc(dc).unwrap();
    assert_eq!(gdi.restore_dc(dc, 0), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.restore_dc(dc, 2), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.restore_dc(dc, -2), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.restore_dc(dc, i32::MIN), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.dc_attr(dc).unwrap().save_level, 1);
}

#[test]
fn a_saved_level_carries_the_selected_objects_and_the_world_transform() {
    let (mut gdi, dc) = context();
    let first = gdi.create_pen(0, 1, 0x00ff00).unwrap();
    let second = gdi.create_pen(0, 1, 0x0000ff).unwrap();
    gdi.select_pen(dc, first).unwrap();
    gdi.save_dc(dc).unwrap();
    gdi.select_pen(dc, second).unwrap();
    gdi.dc_attr_mut_for_test(dc).graphics_mode = GM_ADVANCED;
    gdi.modify_world_transform(dc, Some(Xform { m11: 4.0, m12: 0.0, m21: 0.0, m22: 4.0, dx: 0.0, dy: 0.0 }), MWT_SET).unwrap();
    assert_eq!(gdi.restore_dc(dc, 1), Ok(()));
    assert_eq!(gdi.selected_pen(dc).unwrap().color, 0x00ff00);
    assert_eq!(gdi.dc_attr(dc).unwrap().world_to_wnd, Xform::IDENTITY);
}

#[test]
fn a_restored_level_never_moves_the_surface_extent_or_the_context_kind() {
    let mut gdi = GdiManager::new();
    let dc = gdi.acquire_window_dc(3, 20, 10).unwrap();
    gdi.save_dc(dc).unwrap();
    gdi.resize_dc(dc, 40, 30).unwrap();
    gdi.restore_dc(dc, 1).unwrap();
    let attr = gdi.dc_attr(dc).unwrap();
    assert_eq!(attr.vis_rect, Rect { left: 0, top: 0, right: 40, bottom: 30 });
    assert_eq!(attr.kind, DcKind::Display);
}

#[test]
fn resetting_a_context_drops_every_saved_level() {
    let (mut gdi, dc) = context();
    gdi.save_dc(dc).unwrap();
    gdi.save_dc(dc).unwrap();
    gdi.reset_dc_state(dc).unwrap();
    assert_eq!(gdi.dc_attr(dc).unwrap().save_level, 0);
    assert_eq!(gdi.restore_dc(dc, 1), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.clear_saved_dc(dc), Ok(()));
}
