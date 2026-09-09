//! The control procedure owns a distinct, HWND-scoped scroll state.
use super::*;
use crate::win32_window::{SB_HORZ, SIF_ALL, SIF_POS, SIF_RETURNPREV, SCROLLINFO_BYTES};

#[test]
fn creation_initializes_control_identity_and_disabled_flags() {
    let mut manager = WindowManager::new();
    let window = manager.create(7, None, 0).unwrap();
    assert_eq!(manager.scroll_control_state(window), Err(ScrollError::InvalidBar));
    manager.set_style_bits(window, WS_DISABLED, 0).unwrap();
    manager.initialize_scroll_control(window).unwrap();
    assert_eq!(manager.window_fnid(window), Some(make_fnid(PROC_SCROLLBAR)));
    let state = manager.scroll_control_state(window).unwrap();
    assert_eq!((state.min, state.max, state.page, state.pos, state.flags), (0, 0, 0, 0, ESB_DISABLE_BOTH));
    assert_eq!(manager.owned_scroll_state(window, SB_HORZ).unwrap(), ScrollState::new());
    manager.destroy(window).unwrap();
    assert_eq!(manager.scroll_control_state(window), Err(ScrollError::InvalidWindow));
}

#[test]
fn control_info_clamps_without_sending_another_control_message() {
    let mut manager = WindowManager::new();
    let window = manager.create(7, None, 0).unwrap();
    manager.initialize_scroll_control(window).unwrap();
    let info = ScrollInfo { cb_size: SCROLLINFO_BYTES as u32, mask: SIF_ALL, min: 0, max: 100,
        page: 10, pos: 95, track_pos: 77 };
    let outcome = manager.set_scroll_control_info(window, info, true).unwrap();
    assert_eq!(outcome.result, 91);
    assert!(!outcome.action.control_message && !outcome.action.show && !outcome.action.hide);
    let previous = manager.set_scroll_control_info(window,
        ScrollInfo { mask: SIF_POS | SIF_RETURNPREV, pos: 5, ..info }, false).unwrap();
    assert_eq!(previous.result, 91);
    assert_eq!(manager.scroll_control_state(window).unwrap().pos, 5);
    assert_eq!(manager.owned_scroll_state(window, SB_HORZ).unwrap(), ScrollState::new());
}

#[test]
fn range_message_does_not_clamp_position_or_normalize_endpoints() {
    let mut manager = WindowManager::new();
    let window = manager.create(7, None, 0).unwrap();
    manager.initialize_scroll_control(window).unwrap();
    manager.set_scroll_control_range(window, 20, -10).unwrap();
    let state = manager.scroll_control_state(window).unwrap();
    assert_eq!((state.min, state.max, state.pos), (20, -10, 0));
    assert!(manager.set_scroll_control_flags(window, ESB_DISABLE_BOTH).unwrap());
    assert!(!manager.set_scroll_control_flags(window, ESB_DISABLE_BOTH).unwrap());
}
