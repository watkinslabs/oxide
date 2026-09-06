use super::*;

fn setup() -> (WindowManager, WindowId) {
    let mut state = WindowManager::new();
    let id = state.create(11, None, 0).unwrap();
    state.set_rect(id, WindowRect { left: 100, top: 200, right: 300, bottom: 400 }).unwrap();
    (state, id)
}
fn drain(state: &mut WindowManager, tid: u64) -> Vec<WinMessage> {
    let filter = MessageFilter { hwnd: None, first: 0, last: 0 };
    let mut messages = Vec::new();
    while let Some(message) = state.peek_for_thread(tid, filter, true) { messages.push(message); }
    messages
}

#[test]
fn absolute_motion_updates_existing_cursor_without_duplicate_snapshot_events() {
    let (mut state, id) = setup();
    state.post_compositor_pointer(id, -4, 8, 0, 0).unwrap();
    let messages = drain(&mut state, 11);
    assert_eq!(messages, alloc::vec![WinMessage { hwnd: Some(id), message: WM_MOUSEMOVE, wparam: 0, lparam: mouse_lparam(-4, 8) }]);
    assert_eq!(state.cursor, (96, 208));
    state.post_compositor_pointer(id, -4, 8, 0, 0).unwrap();
    assert!(drain(&mut state, 11).is_empty());
}

#[test]
fn transitions_emit_down_and_up_once_with_progressive_modifier_and_button_flags() {
    let (mut state, id) = setup();
    state.post_compositor_pointer(id, 0, 0, 0, 0).unwrap(); drain(&mut state, 11);
    state.post_compositor_pointer(id, 0, 0, (MK_LBUTTON | MK_RBUTTON | MK_SHIFT) as u32, 0).unwrap();
    let messages = drain(&mut state, 11);
    assert_eq!(messages.iter().map(|m| (m.message, m.wparam)).collect::<Vec<_>>(), alloc::vec![
        (WM_MOUSEMOVE, MK_SHIFT as u64),
        (WM_LBUTTONDOWN, (MK_SHIFT | MK_LBUTTON) as u64),
        (WM_RBUTTONDOWN, (MK_SHIFT | MK_LBUTTON | MK_RBUTTON) as u64)]);
    state.post_compositor_pointer(id, 0, 0, (MK_RBUTTON | MK_SHIFT) as u32, 0).unwrap();
    let messages = drain(&mut state, 11);
    assert_eq!(messages.len(), 1);
    assert_eq!((messages[0].message, messages[0].wparam), (WM_LBUTTONUP, (MK_RBUTTON | MK_SHIFT) as u64));
    assert_eq!(state.buttons, MK_RBUTTON | MK_SHIFT);
}

#[test]
fn capture_routes_to_capture_thread_and_converts_client_coordinates_but_not_wheel() {
    let (mut state, source) = setup();
    let capture = state.create(22, None, 0).unwrap();
    state.set_rect(capture, WindowRect { left: 400, top: 500, right: 600, bottom: 700 }).unwrap();
    state.set_capture(22, capture).unwrap();
    state.post_compositor_pointer(source, 10, 20, MK_LBUTTON as u32, -120).unwrap();
    assert!(drain(&mut state, 11).is_empty());
    let messages = drain(&mut state, 22);
    assert_eq!(messages.len(), 3);
    assert!(messages.iter().all(|m| m.hwnd == Some(capture)));
    assert_eq!((messages[0].message, messages[0].lparam), (WM_MOUSEMOVE, mouse_lparam(-290, -280)));
    assert_eq!((messages[1].message, messages[1].lparam), (WM_LBUTTONDOWN, mouse_lparam(-290, -280)));
    assert_eq!((messages[2].message, messages[2].lparam, messages[2].wparam),
        (WM_MOUSEWHEEL, mouse_lparam(110, 220), MK_LBUTTON as u64 | ((-120i16 as u16 as u64) << 16)));
}

#[test]
fn xbuttons_encode_identity_in_high_word_and_preserve_low_word_state() {
    let (mut state, id) = setup();
    state.post_compositor_pointer(id, 0, 0, (MK_XBUTTON1 | MK_XBUTTON2) as u32, 0).unwrap();
    let messages = drain(&mut state, 11);
    assert_eq!((messages[1].message, messages[1].wparam), (WM_XBUTTONDOWN, MK_XBUTTON1 as u64 | ((XBUTTON1 as u64) << 16)));
    assert_eq!((messages[2].message, messages[2].wparam), (WM_XBUTTONDOWN, (MK_XBUTTON1 | MK_XBUTTON2) as u64 | ((XBUTTON2 as u64) << 16)));
    state.post_compositor_pointer(id, 0, 0, MK_XBUTTON2 as u32, 0).unwrap();
    assert_eq!(drain(&mut state, 11)[0].wparam, MK_XBUTTON2 as u64 | ((XBUTTON1 as u64) << 16));
}

#[test]
fn capture_release_and_destroy_restore_source_routing() {
    let (mut state, source) = setup();
    let capture = state.create(22, None, 0).unwrap();
    state.set_capture(22, capture).unwrap();
    assert!(state.release_capture(22).unwrap());
    state.post_compositor_pointer(source, 1, 1, 0, 0).unwrap();
    assert_eq!(drain(&mut state, 11)[0].hwnd, Some(source));
    state.set_capture(22, capture).unwrap(); state.destroy(capture).unwrap();
    state.post_compositor_pointer(source, 2, 2, 0, 0).unwrap();
    assert_eq!(drain(&mut state, 11)[0].hwnd, Some(source));
}

#[test]
fn full_queue_cannot_partially_publish_motion_buttons_or_wheel() {
    let (mut state, id) = setup();
    let message = WinMessage { hwnd: Some(id), message: WM_CLOSE, wparam: 0, lparam: 0 };
    for _ in 0..MESSAGE_QUEUE_LIMIT - 1 { state.post_to_window(id, message).unwrap(); }
    assert_eq!(state.post_compositor_pointer(id, 1, 2, MK_LBUTTON as u32, 120), Err(WindowError::QueueFull));
    assert_eq!(state.cursor, (0, 0)); assert_eq!(state.buttons, 0);
    assert_eq!(drain(&mut state, 11).len(), MESSAGE_QUEUE_LIMIT - 1);
    state.post_compositor_pointer(id, 1, 2, MK_LBUTTON as u32, 120).unwrap();
    assert_eq!(drain(&mut state, 11).len(), 3);
}

#[test]
fn malformed_pointer_and_stale_source_leave_canonical_state_unchanged() {
    let (mut state, id) = setup();
    for (x, buttons, wheel) in [(i32::MAX, 0, 0), (0, 1 << 8, 0), (0, 0, 32768)] {
        assert_eq!(state.post_compositor_pointer(id, x, 0, buttons, wheel), Err(WindowError::InvalidParent));
    }
    assert_eq!(state.cursor, (0, 0)); assert_eq!(state.buttons, 0);
    assert!(drain(&mut state, 11).is_empty());
    state.destroy(id).unwrap();
    assert_eq!(state.post_compositor_pointer(id, 0, 0, 0, 0), Err(WindowError::NoSuchWindow));
}
