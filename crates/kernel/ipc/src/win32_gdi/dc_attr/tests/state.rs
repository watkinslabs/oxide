use super::*;
use crate::win32_gdi::{Xform, Size};

#[test]
fn a_new_attribute_block_carries_the_documented_initial_state() {
    let attr = DcAttr::new();
    assert_eq!(attr.map_mode, MM_TEXT);
    assert_eq!(attr.graphics_mode, GM_COMPATIBLE);
    assert_eq!(attr.arc_direction, AD_COUNTERCLOCKWISE);
    assert_eq!(attr.miter_limit, DEFAULT_MITER_LIMIT);
    assert_eq!(attr.wnd_ext, Size { cx: 1, cy: 1 });
    assert_eq!(attr.vport_ext, Size { cx: 1, cy: 1 });
    assert_eq!(attr.world_to_wnd, Xform::IDENTITY);
    assert!(attr.vport_to_world_valid);
    assert_eq!(attr.save_level, 0);
    assert!(rect_is_empty(&attr.bounds));
}

#[test]
fn reset_restores_initial_state_but_keeps_the_surface_extent() {
    let mut attr = DcAttr::new();
    attr.set_vis_rect(300, 200);
    attr.miter_limit = 3.0;
    attr.save_level = 4;
    attr.pixel_format = 2;
    attr.reset();
    assert_eq!(attr.vis_rect, Rect { left: 0, top: 0, right: 300, bottom: 200 });
    assert_eq!(attr.miter_limit, DEFAULT_MITER_LIMIT);
    assert_eq!(attr.save_level, 0);
    // A chosen pixel format outlives a reset: it belongs to the surface.
    assert_eq!(attr.pixel_format, 2);
}
