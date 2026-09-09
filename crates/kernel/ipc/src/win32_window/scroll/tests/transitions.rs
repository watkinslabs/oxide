//! SCROLLINFO masks decide flags, visibility and redraw independently.
use super::*;
const INFO: ScrollInfo = ScrollInfo { cb_size: SCROLLINFO_BYTES as u32, mask: SIF_ALL,
    min: 0, max: 100, page: 10, pos: 50, track_pos: 0 };
fn state() -> ScrollState { ScrollState { min: 0, max: 100, page: 10, pos: 50,
    visible: true, ..ScrollState::new() } }

#[test]
fn zero_page_never_admits_a_position_past_maximum() {
    let mut state = state();
    assert_eq!(state.apply_for_bar(SB_CTL, ScrollInfo { page: 0, pos: 101, ..INFO }, false).unwrap().result, 100);
}
#[test]
fn disable_no_scroll_preserves_visibility_and_updates_arrow_flags() {
    let mut state = state();
    let result = state.apply_for_bar(SB_VERT, ScrollInfo { mask: SIF_RANGE | SIF_DISABLENOSCROLL,
        max: 0, ..INFO }, false).unwrap();
    assert!(state.visible && state.flags == ESB_DISABLE_BOTH);
    assert_eq!(state.flags, ESB_DISABLE_BOTH);
    assert!(result.action.disable_arrows && result.action.repaint && !result.action.hide);
}
#[test]
fn no_fields_does_not_change_arrow_flags_or_visibility() {
    let mut state = ScrollState { page: 1, visible: true, ..ScrollState::new() };
    let before = state;
    state.apply_for_bar(SB_VERT, ScrollInfo { mask: SIF_DISABLENOSCROLL, ..INFO }, false).unwrap();
    assert_eq!(state, before);
}
#[test]
fn page_only_can_hide_but_does_not_show_or_enable() {
    let mut state = state();
    let hidden = state.apply_for_bar(SB_VERT, ScrollInfo { mask: SIF_PAGE, page: 101, ..INFO }, false).unwrap();
    assert!(hidden.action.hide && !state.visible);
    state.flags = ESB_DISABLE_BOTH;
    let unhidden = state.apply_for_bar(SB_VERT, ScrollInfo { mask: SIF_PAGE, page: 1, ..INFO }, false).unwrap();
    assert!(!unhidden.action.show && !state.visible && state.flags == ESB_DISABLE_BOTH);
    assert_eq!(state.flags, ESB_DISABLE_BOTH);
}
#[test]
fn a_scrollable_range_enables_previously_disabled_arrows() {
    let mut state = state(); state.flags = ESB_DISABLE_BOTH;
    let enabled = state.apply_for_bar(SB_VERT, ScrollInfo { mask: SIF_RANGE, ..INFO }, false).unwrap();
    assert_eq!(state.flags, ESB_ENABLE_BOTH);
    assert!(state.flags == ESB_ENABLE_BOTH && enabled.action.enable_arrows && enabled.action.repaint);
}
#[test]
fn identical_info_with_redraw_still_requests_paint() {
    let mut state = state();
    assert!(state.apply_for_bar(SB_VERT, INFO, true).unwrap().action.repaint);
    assert!(!state.apply_for_bar(SB_VERT, INFO, false).unwrap().action.repaint);
}
