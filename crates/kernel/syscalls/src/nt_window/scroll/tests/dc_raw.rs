//! Scroll geometry: source, destination and the area left needing repaint.
use super::*;

const BOX: WindowRect = WindowRect { left: 0, top: 0, right: 100, bottom: 100 };
fn rect(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }

#[test]
fn a_downward_scroll_moves_the_top_of_the_area_and_leaves_a_strip_at_the_top() {
    let plan = plan(BOX, None, None, 0, 10);
    assert_eq!(plan.source, rect(0, 0, 100, 90));
    assert_eq!(plan.destination, rect(0, 10, 100, 100));
    assert_eq!(plan.covered, BOX);
    let region = update_region(plan).unwrap();
    assert_eq!(region.bounds(), Some(rect(0, 0, 100, 10)));
}

#[test]
fn a_rightward_scroll_leaves_a_strip_on_the_left() {
    let plan = plan(BOX, None, None, 25, 0);
    assert_eq!(plan.source, rect(0, 0, 75, 100));
    assert_eq!(plan.destination, rect(25, 0, 100, 100));
    assert_eq!(update_region(plan).unwrap().bounds(), Some(rect(0, 0, 25, 100)));
}

#[test]
fn a_scroll_rectangle_narrows_both_the_move_and_the_covered_area() {
    let plan = plan(BOX, Some(rect(10, 10, 60, 60)), None, 0, 5);
    assert_eq!(plan.source, rect(10, 10, 60, 60));
    assert_eq!(plan.destination, rect(10, 15, 60, 65));
    assert_eq!(plan.covered, rect(10, 10, 60, 60));
    assert_eq!(update_region(plan).unwrap().bounds(), Some(rect(10, 10, 60, 15)));
}

#[test]
fn a_clipping_rectangle_bounds_the_move_without_the_device_clip_box() {
    let plan = plan(BOX, None, Some(rect(20, 20, 80, 80)), 0, 10);
    assert_eq!(plan.source, rect(20, 20, 80, 70));
    assert_eq!(plan.destination, rect(20, 30, 80, 80));
    assert_eq!(plan.covered, rect(20, 20, 80, 80));
}

#[test]
fn naming_both_rectangles_covers_only_their_intersection() {
    let plan = plan(BOX, Some(rect(0, 0, 50, 50)), Some(rect(25, 25, 100, 100)), 0, 5);
    assert_eq!(plan.covered, rect(25, 25, 50, 50));
}

#[test]
fn a_scroll_that_moves_everything_out_leaves_nothing_to_move() {
    let plan = plan(BOX, None, None, 0, 200);
    assert!(is_empty(plan.source));
    assert_eq!(update_region(plan).unwrap().bounds(), Some(BOX));
}

#[test]
fn a_scroll_of_nothing_leaves_nothing_needing_repaint() {
    let plan = plan(BOX, None, None, 0, 0);
    assert_eq!(plan.source, BOX);
    assert_eq!(plan.destination, BOX);
    assert!(update_region(plan).unwrap().is_empty());
}

#[test]
fn an_overshoot_is_a_distance_wider_than_the_area_it_moves_within() {
    assert!(!overshoots(BOX, 100, 0));
    assert!(overshoots(BOX, 101, 0));
    assert!(overshoots(BOX, 0, -101));
    assert!(!overshoots(BOX, -100, 100));
}

#[test]
fn the_redraw_only_erases_when_both_flags_are_named() {
    assert_eq!(redraw_flags(0), ipc::win32_window::RDW_INVALIDATE);
    assert_eq!(redraw_flags(SW_ERASE), ipc::win32_window::RDW_INVALIDATE);
    assert_eq!(redraw_flags(SW_INVALIDATE), ipc::win32_window::RDW_INVALIDATE);
    assert_eq!(redraw_flags(SW_ERASE | SW_INVALIDATE), ipc::win32_window::RDW_INVALIDATE | ipc::win32_window::RDW_ERASE);
}

#[test]
fn the_update_region_is_wanted_whenever_any_output_or_repaint_is_asked_for() {
    assert!(!wants_update(0, 0, 0));
    assert!(!wants_update(0, 0, SW_SCROLLCHILDREN | SW_NODCCACHE));
    assert!(wants_update(1, 0, 0));
    assert!(wants_update(0, 1, 0));
    assert!(wants_update(0, 0, SW_INVALIDATE));
    assert!(wants_update(0, 0, SW_ERASE));
}

#[test]
fn the_union_of_an_empty_area_is_the_other_area() {
    assert_eq!(union(rect(0, 0, 0, 0), BOX), BOX);
    assert_eq!(union(BOX, rect(0, 0, 0, 0)), BOX);
    assert_eq!(union(rect(0, 0, 10, 10), rect(20, 20, 30, 30)), rect(0, 0, 30, 30));
}
