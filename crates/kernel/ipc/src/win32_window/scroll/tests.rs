use super::*;
use crate::win32_window::WindowManager;
use crate::win32_window::WS_VISIBLE;

const INFO: ScrollInfo = ScrollInfo { cb_size: SCROLLINFO_BYTES as u32, mask: SIF_ALL, min: 0, max: 100, page: 10, pos: 95, track_pos: 77 };

#[test]
fn set_clamps_position_to_range_minus_page() {
    let mut state = ScrollState::new();
    assert_eq!(state.apply(INFO), Ok(91));
    assert_eq!(state.pos, 91);
}

#[test]
fn return_previous_is_explicit_and_get_masks_fields() {
    let mut state = ScrollState::new();
    state.apply(INFO).unwrap();
    let mut get = ScrollInfo { cb_size: SCROLLINFO_BYTES as u32, mask: SIF_POS | SIF_TRACKPOS, min: -1, max: -1, page: 0, pos: 0, track_pos: 0 };
    assert_eq!(state.fill(&mut get), Ok(true));
    assert_eq!((get.pos, get.track_pos), (91, 91));
}

#[test]
fn track_input_is_ignored_and_live_tracking_controls_get_output() {
    let mut state = ScrollState::new();
    state.apply(INFO).unwrap();
    assert_eq!(state.track_pos, 0);
    state.tracking = true;
    state.track_pos = 77;
    let mut get = ScrollInfo { cb_size: SCROLLINFO_BYTES as u32, mask: SIF_TRACKPOS, min: 0, max: 0, page: 0, pos: 0, track_pos: 0 };
    state.fill(&mut get).unwrap();
    assert_eq!(get.track_pos, 77);
}

#[test]
fn no_scroll_hides_nonclient_bar_but_control_bar_uses_message_action() {
    let mut state = ScrollState::new();
    state.visible = true;
    let outcome = state.apply_for_bar(SB_VERT, ScrollInfo { cb_size: 28, mask: SIF_RANGE | SIF_PAGE, min: 0, max: 0, page: 1, pos: 0, track_pos: 0 }, true).unwrap();
    assert!(outcome.action.hide);
    let control = state.apply_for_bar(SB_CTL, INFO, true).unwrap();
    assert!(control.action.control_message);
    assert!(!control.action.show && !control.action.hide);
}

#[test]
fn invalid_masks_and_bars_are_rejected() {
    assert!(!ScrollInfo { cb_size: 20, mask: SIF_POS, min: 0, max: 0, page: 0, pos: 0, track_pos: 0 }.valid());
    assert!(!valid_bar(3));
}

#[test]
fn owner_helpers_keep_scroll_state_with_the_window_lifetime() {
    let mut manager = WindowManager::new();
    let hwnd = manager.create(7, None, 0).unwrap();
    manager.set_window_styles(hwnd, 0x0020_0000, 0).unwrap();
    let set = ScrollInfo { cb_size: 24, mask: SIF_RANGE | SIF_PAGE | SIF_POS, min: 0, max: 100, page: 10, pos: 90, track_pos: 0 };
    assert_eq!(manager.set_owned_scroll_info(hwnd, SB_VERT, set, true).unwrap().result, 90);
    let mut get = ScrollInfo { cb_size: 24, mask: SIF_RANGE | SIF_PAGE | SIF_POS, min: -1, max: -1, page: 0, pos: 0, track_pos: 123 };
    assert!(manager.get_owned_scroll_info(hwnd, SB_VERT, &mut get).unwrap());
    assert_eq!((get.min, get.max, get.page, get.pos, get.track_pos), (0, 100, 10, 90, 123));
    assert_eq!(manager.destroy(hwnd).unwrap().owner_tid, 7);
}

#[test]
fn get_standard_scroll_info_rejects_a_missing_style_bar() {
    let mut manager = WindowManager::new();
    let window = manager.create(7, None, 0).unwrap();
    let mut info = INFO;
    assert!(!manager.get_owned_scroll_info(window, SB_VERT, &mut info).unwrap());
    manager.set_window_styles(window, 0x0020_0000, 0).unwrap();
    assert!(manager.get_owned_scroll_info(window, SB_VERT, &mut info).unwrap());
}

#[test]
fn scrollbar_style_does_not_hide_parent_or_edit_window() {
    let mut manager = WindowManager::new();
    let parent = manager.create(7, None, 0).unwrap();
    let edit = manager.create(7, Some(parent), 0).unwrap();
    manager.set_window_styles(parent, WS_VISIBLE | 0x0001_0000, 0x40).unwrap();
    manager.set_window_styles(edit, WS_VISIBLE | 0x0000_0001, 0x80).unwrap();
    let parent_before = manager.window_styles(parent).unwrap();
    let edit_before = manager.window_styles(edit).unwrap();
    manager.set_scrollbar_style(edit, SB_VERT, true).unwrap();
    let parent_after = manager.window_styles(parent).unwrap();
    let edit_after = manager.window_styles(edit).unwrap();
    assert_eq!(parent_after, parent_before);
    assert_eq!(edit_after.0 & !0x0020_0000, edit_before.0);
    assert_eq!(edit_after.1, edit_before.1);
    assert!(manager.get(edit).unwrap().visible == manager.get(parent).unwrap().visible);
}

#[test]
fn style_initializes_query_visibility_and_set_scroll_info_hides_it() {
    let mut manager = WindowManager::new();
    let window = manager.create(7, None, 0).unwrap();
    manager.set_window_styles(window, 0x0020_0000, 0).unwrap();
    assert!(manager.owned_scroll_state(window, SB_VERT).unwrap().visible);

    let no_scroll = ScrollInfo { cb_size: SCROLLINFO_BYTES as u32, mask: SIF_RANGE | SIF_PAGE,
        min: 0, max: 0, page: 1, pos: 0, track_pos: 0 };
    let outcome = manager.set_owned_scroll_info(window, SB_VERT, no_scroll, true).unwrap();
    assert!(outcome.action.hide);
    manager.set_scrollbar_style(window, SB_VERT, false).unwrap();
    assert!(!manager.owned_scroll_state(window, SB_VERT).unwrap().visible);
    assert_eq!(manager.window_styles(window).unwrap().0 & 0x0020_0000, 0);
}
