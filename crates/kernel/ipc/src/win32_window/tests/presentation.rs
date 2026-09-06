use super::*;

#[test]
fn readiness_is_owned_by_window_creation_ack_and_lifetime() {
    let mut state = WindowManager::new();
    let id = state.create(1, None, 0).unwrap();
    assert_eq!(state.presentation_ready(id), Some(false));
    state.set_text(id, &[65]).unwrap();
    state.set_rect(id, WindowRect { left: 0, top: 0, right: 100, bottom: 100 }).unwrap();
    assert_eq!(state.presentation_ready(id), Some(false));
    state.set_presentation_ready(id, true).unwrap();
    assert!(state.get(id).unwrap().presentation_ready);
    state.set_presentation_ready(id, false).unwrap();
    assert_eq!(state.presentation_ready(id), Some(false));
    state.destroy(id).unwrap();
    assert_eq!(state.presentation_ready(id), None);
    assert_eq!(state.set_presentation_ready(id, true), Err(WindowError::NoSuchWindow));
    let next = state.create(1, None, 0).unwrap();
    assert_eq!(state.presentation_ready(next), Some(false));
}

#[test]
fn styles_are_canonical_persist_past_presentation_ack_and_die_with_hwnd() {
    let mut state = WindowManager::new();
    let id = state.create(1, None, 0).unwrap();
    assert_eq!(state.window_styles(id), Some((0, 0)));
    assert_eq!(state.set_window_styles(id, 0x5000_0000, 0x200), Ok((0, 0)));
    state.set_presentation_ready(id, true).unwrap();
    assert_eq!(state.window_styles(id), Some((0x5000_0000, 0x200)));
    assert_eq!((state.get(id).unwrap().style, state.get(id).unwrap().ex_style), (0x5000_0000, 0x200));
    assert_eq!(state.set_window_styles(id, 0x4000_0000, 0), Ok((0x5000_0000, 0x200)));
    state.destroy(id).unwrap();
    assert_eq!(state.window_styles(id), None);
    assert_eq!(state.set_window_styles(id, 1, 2), Err(WindowError::NoSuchWindow));
}

#[test]
fn requested_visibility_is_not_committed_until_show_and_hide_synchronizes_style() {
    let mut state = WindowManager::new();
    let id = state.create(1, None, 0).unwrap();
    state.set_window_styles(id, WS_VISIBLE | 0x4000_0000, 0x200).unwrap();
    assert!(!state.get(id).unwrap().visible);
    state.set_presentation_ready(id, true).unwrap();
    assert!(!state.get(id).unwrap().visible);
    state.show(1, id, true).unwrap();
    assert!(state.get(id).unwrap().visible);
    assert_eq!(state.window_styles(id), Some((WS_VISIBLE | 0x4000_0000, 0x200)));
    state.show(1, id, false).unwrap();
    assert!(!state.get(id).unwrap().visible);
    assert_eq!(state.window_styles(id), Some((0x4000_0000, 0x200)));
    state.set_window_styles(id, WS_VISIBLE, 0).unwrap();
    state.show(1, id, false).unwrap();
    assert_eq!(state.window_styles(id), Some((0, 0)));
}

#[test]
fn full_posted_queue_does_not_block_canonical_paint_readiness_on_show() {
    let mut state = WindowManager::new();
    let id = state.create(1, None, 0).unwrap();
    state.set_rect(id, WindowRect { left: 0, top: 0, right: 100, bottom: 100 }).unwrap();
    state.set_window_styles(id, 0x4000_0000, 0x200).unwrap();
    let message = WinMessage { hwnd: Some(id), message: WM_CLOSE, wparam: 0, lparam: 0 };
    while state.post_to_window(id, message).is_ok() {}
    assert_eq!(state.show(1, id, true), Ok(false));
    assert!(state.get(id).unwrap().visible);
    assert_eq!(state.window_styles(id), Some((WS_VISIBLE | 0x4000_0000, 0x200)));
    assert_eq!(state.post_to_window(id, message), Err(WindowError::QueueFull));
    let filter = MessageFilter { hwnd: Some(id), first: WM_PAINT, last: WM_PAINT };
    assert_eq!(state.peek_for_thread(1, filter, true).unwrap().message, WM_PAINT);
    state.begin_paint(id).unwrap();
    assert!(state.peek_for_thread(1, filter, true).is_none());
}
