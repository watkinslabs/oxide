use super::*;

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }

#[test]
fn every_window_with_a_procedure_is_handed_its_own_window_rectangle() {
    let window = rect(10, 20, 210, 220);
    assert_eq!(creation_nccalcsize(0x1400042c0, window), Some(window));
}

#[test]
fn a_class_without_a_procedure_runs_no_creation_calculation() {
    assert_eq!(creation_nccalcsize(0, rect(0, 0, 100, 100)), None);
}

#[test]
fn an_inverted_window_rectangle_runs_no_creation_calculation() {
    assert_eq!(creation_nccalcsize(1, rect(0, 0, -1, 100)), None);
    assert_eq!(creation_nccalcsize(1, rect(0, 0, 100, -1)), None);
}

#[test]
fn the_reply_becomes_the_client_rectangle_and_reserves_the_band() {
    let window = rect(0, 0, 729, 546);
    let reserved = rect(0, 19, 729, 546);
    assert_eq!(creation_client_rect(window, window, reserved), reserved);
    assert_eq!(menu_bar_band(window.top, reserved.top, true), Some((0, 19)));
}

#[test]
fn an_ill_formed_reply_leaves_the_client_area_equal_to_the_window() {
    let window = rect(0, 0, 729, 546);
    assert_eq!(creation_client_rect(window, window, rect(0, 600, 729, 546)), window);
}

#[test]
fn a_window_moved_while_the_calculation_ran_adopts_the_reply_in_its_own_space() {
    // The calculation is handed the rectangle the window had; a window
    // manager places the window before the reply comes back. Adopting the
    // reply verbatim would leave the client area naming the previous space,
    // and the client origin - where every child of this window is presented -
    // would then be a large negative offset that puts those children over the
    // nonclient band.
    let handed = rect(0, 0, 729, 528);
    let reserved = rect(0, 19, 729, 528);
    let moved = rect(148, 146, 877, 674);
    assert_eq!(creation_client_rect(handed, moved, reserved), rect(148, 165, 877, 674));
    assert_eq!(client_origin(moved, creation_client_rect(handed, moved, reserved)), (0, 19));
}

#[test]
fn the_client_origin_is_the_offset_a_child_is_presented_at() {
    assert_eq!(client_origin(rect(0, 0, 729, 546), rect(0, 19, 729, 546)), (0, 19));
    assert_eq!(client_origin(rect(5, 7, 100, 100), rect(5, 7, 100, 100)), (0, 0));
}
