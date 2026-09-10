//! Scrollbar accessibility state per part.
use super::super::super::*;
use super::{scrollbar_states, STATE_SYSTEM_INVISIBLE, STATE_SYSTEM_OFFSCREEN, STATE_SYSTEM_PRESSED, STATE_SYSTEM_UNAVAILABLE};

fn scrollable() -> ScrollState {
    ScrollState { min: 0, max: 100, page: 10, pos: 50, track_pos: 50, tracking: false, visible: true, flags: ESB_ENABLE_BOTH }
}

#[test]
fn a_styled_bar_with_range_reports_no_state_at_all() {
    let parts = scrollbar_states(scrollable(), SB_VERT, true, true);
    assert_eq!(parts, [0, 0, 0, 0, 0, 0]);
    assert_eq!(STATE_SYSTEM_PRESSED, 0x0000_0008);
}

#[test]
fn a_bar_the_style_does_not_carry_is_invisible() {
    let parts = scrollbar_states(scrollable(), SB_VERT, false, true);
    assert_eq!(parts[0], STATE_SYSTEM_INVISIBLE);
}

#[test]
fn a_range_with_nothing_to_scroll_is_unavailable_or_offscreen() {
    let mut state = scrollable();
    state.max = 5; state.page = 10;
    assert_eq!(scrollbar_states(state, SB_VERT, true, true)[0], STATE_SYSTEM_UNAVAILABLE);
    assert_eq!(scrollbar_states(state, SB_VERT, false, true)[0], STATE_SYSTEM_INVISIBLE | STATE_SYSTEM_OFFSCREEN);
}

#[test]
fn a_disabled_scrollbar_control_is_unavailable() {
    assert_eq!(scrollbar_states(scrollable(), SB_CTL, true, false)[0], STATE_SYSTEM_UNAVAILABLE);
    assert_eq!(scrollbar_states(scrollable(), SB_CTL, true, true)[0], 0);
}

#[test]
fn each_disabled_arrow_marks_only_its_own_part() {
    let mut state = scrollable();
    state.flags = ESB_DISABLE_LTUP;
    assert_eq!(scrollbar_states(state, SB_VERT, true, true)[1], STATE_SYSTEM_UNAVAILABLE);
    assert_eq!(scrollbar_states(state, SB_VERT, true, true)[5], 0);
    state.flags = ESB_DISABLE_RTDN;
    assert_eq!(scrollbar_states(state, SB_VERT, true, true)[1], 0);
    assert_eq!(scrollbar_states(state, SB_VERT, true, true)[5], STATE_SYSTEM_UNAVAILABLE);
}

#[test]
fn the_page_regions_vanish_at_the_ends_of_the_range() {
    let mut state = scrollable();
    state.pos = state.min;
    assert_eq!(scrollbar_states(state, SB_VERT, true, true)[2], STATE_SYSTEM_INVISIBLE);
    state.pos = state.max - 1;
    assert_eq!(scrollbar_states(state, SB_VERT, true, true)[4], STATE_SYSTEM_INVISIBLE);
    assert_eq!(scrollbar_states(state, SB_VERT, true, true)[2], 0);
}
