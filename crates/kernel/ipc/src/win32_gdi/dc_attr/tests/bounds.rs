use super::*;
use crate::win32_gdi::Size;

#[test]
fn an_empty_accumulator_absorbs_the_first_rectangle_exactly() {
    let mut bounds = empty_bounds();
    assert!(rect_is_empty(&bounds));
    add_bounds_rect(&mut bounds, &Rect { left: 0, top: 0, right: 0, bottom: 5 });
    assert!(rect_is_empty(&bounds), "a zero-width rectangle contributes nothing");
    add_bounds_rect(&mut bounds, &Rect { left: 3, top: 4, right: 8, bottom: 9 });
    assert_eq!(bounds, Rect { left: 3, top: 4, right: 8, bottom: 9 });
    add_bounds_rect(&mut bounds, &Rect { left: 1, top: 6, right: 5, bottom: 12 });
    assert_eq!(bounds, Rect { left: 1, top: 4, right: 8, bottom: 12 });
}

#[test]
fn reading_empty_bounds_reports_a_zeroed_rectangle_and_the_reset_state() {
    let mut attr = DcAttr::new();
    attr.set_vis_rect(100, 100);
    assert_eq!(attr.get_bounds_rect(true, 0), (DCB_RESET, Some(Rect { left: 0, top: 0, right: 0, bottom: 0 })));
}

#[test]
fn reading_without_a_rectangle_reports_nothing_but_still_honours_reset() {
    let mut attr = DcAttr::new();
    attr.set_vis_rect(100, 100);
    attr.bounds_enabled = true;
    attr.accumulate_bounds(Rect { left: 1, top: 2, right: 3, bottom: 4 });
    assert_eq!(attr.get_bounds_rect(false, DCB_RESET), (0, None));
    assert!(rect_is_empty(&attr.bounds));
}

#[test]
fn accumulated_bounds_are_clamped_to_the_visible_rectangle() {
    let mut attr = DcAttr::new();
    attr.set_vis_rect(50, 40);
    attr.bounds_enabled = true;
    attr.accumulate_bounds(Rect { left: -10, top: -20, right: 500, bottom: 400 });
    assert_eq!(attr.get_bounds_rect(true, 0), (DCB_SET, Some(Rect { left: 0, top: 0, right: 50, bottom: 40 })));
    // Reading without the reset flag leaves the accumulator in place.
    assert_eq!(attr.get_bounds_rect(true, DCB_RESET).0, DCB_SET);
    assert_eq!(attr.get_bounds_rect(true, 0), (DCB_RESET, Some(Rect { left: 0, top: 0, right: 0, bottom: 0 })));
}

#[test]
fn accumulation_only_records_while_enabled() {
    let mut attr = DcAttr::new();
    attr.set_vis_rect(50, 40);
    attr.accumulate_bounds(Rect { left: 1, top: 1, right: 9, bottom: 9 });
    assert!(rect_is_empty(&attr.bounds));
    assert_eq!(attr.set_bounds_rect(None, DCB_ENABLE), DCB_DISABLE | DCB_RESET);
    attr.accumulate_bounds(Rect { left: 1, top: 1, right: 9, bottom: 9 });
    assert_eq!(attr.bounds, Rect { left: 1, top: 1, right: 9, bottom: 9 });
    assert_eq!(attr.set_bounds_rect(None, 0), DCB_ENABLE | DCB_SET);
}

#[test]
fn enabling_and_disabling_together_is_refused() {
    let mut attr = DcAttr::new();
    assert_eq!(attr.set_bounds_rect(None, DCB_ENABLE | DCB_DISABLE), 0);
    assert!(!attr.bounds_enabled);
}

#[test]
fn an_accumulate_request_converts_its_rectangle_to_device_space() {
    let mut attr = DcAttr::new();
    attr.set_vis_rect(100, 100);
    attr.vport_ext = Size { cx: 2, cy: 2 };
    attr.update_xforms();
    attr.set_bounds_rect(Some(Rect { left: 1, top: 2, right: 3, bottom: 4 }), DCB_ACCUMULATE);
    assert_eq!(attr.bounds, Rect { left: 2, top: 4, right: 6, bottom: 8 });
    // Accumulation works whether or not tracking is enabled, unlike drawing.
    assert!(!attr.bounds_enabled);
}

#[test]
fn a_disable_request_stops_tracking_and_reports_the_previous_state() {
    let mut attr = DcAttr::new();
    attr.set_bounds_rect(None, DCB_ENABLE);
    assert_eq!(attr.set_bounds_rect(None, DCB_DISABLE), DCB_ENABLE | DCB_RESET);
    assert!(!attr.bounds_enabled);
}
