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
    state.post_compositor_pointer(id, -4, 8, 0, 0, 0).unwrap();
    let messages = drain(&mut state, 11);
    // The queue carries the screen point; the hit test at retrieval is what
    // translates a client hit into client coordinates.
    assert_eq!(messages, alloc::vec![WinMessage { hwnd: Some(id), message: WM_MOUSEMOVE, wparam: 0, lparam: mouse_lparam(96, 208) }]);
    assert_eq!(state.cursor, (96, 208));
    state.post_compositor_pointer(id, -4, 8, 0, 0, 0).unwrap();
    assert!(drain(&mut state, 11).is_empty());
}

#[test]
fn transitions_emit_down_and_up_once_with_progressive_modifier_and_button_flags() {
    let (mut state, id) = setup();
    state.post_compositor_pointer(id, 0, 0, 0, 0, 0).unwrap(); drain(&mut state, 11);
    state.post_compositor_pointer(id, 0, 0, (MK_LBUTTON | MK_RBUTTON | MK_SHIFT) as u32, 0, 0).unwrap();
    let messages = drain(&mut state, 11);
    assert_eq!(messages.iter().map(|m| (m.message, m.wparam)).collect::<Vec<_>>(), alloc::vec![
        (WM_MOUSEMOVE, MK_SHIFT as u64),
        (WM_LBUTTONDOWN, (MK_SHIFT | MK_LBUTTON) as u64),
        (WM_RBUTTONDOWN, (MK_SHIFT | MK_LBUTTON | MK_RBUTTON) as u64)]);
    state.post_compositor_pointer(id, 0, 0, (MK_RBUTTON | MK_SHIFT) as u32, 0, 0).unwrap();
    let messages = drain(&mut state, 11);
    assert_eq!(messages.len(), 1);
    assert_eq!((messages[0].message, messages[0].wparam), (WM_LBUTTONUP, (MK_RBUTTON | MK_SHIFT) as u64));
    assert_eq!(state.buttons, MK_RBUTTON | MK_SHIFT);
}

#[test]
fn capture_routes_to_capture_thread_and_queues_the_screen_point() {
    let (mut state, source) = setup();
    let capture = state.create(22, None, 0).unwrap();
    state.set_rect(capture, WindowRect { left: 400, top: 500, right: 600, bottom: 700 }).unwrap();
    state.set_capture(22, capture).unwrap();
    state.post_compositor_pointer(source, 10, 20, MK_LBUTTON as u32, -120, 0).unwrap();
    assert!(drain(&mut state, 11).is_empty());
    let messages = drain(&mut state, 22);
    assert_eq!(messages.len(), 3);
    assert!(messages.iter().all(|m| m.hwnd == Some(capture)));
    // Capture redirects delivery, not the space the point is in: the screen
    // point stands whichever window the message is handed to.
    assert_eq!((messages[0].message, messages[0].lparam), (WM_MOUSEMOVE, mouse_lparam(110, 220)));
    assert_eq!((messages[1].message, messages[1].lparam), (WM_LBUTTONDOWN, mouse_lparam(110, 220)));
    assert_eq!((messages[2].message, messages[2].lparam, messages[2].wparam),
        (WM_MOUSEWHEEL, mouse_lparam(110, 220), MK_LBUTTON as u64 | ((-120i16 as u16 as u64) << 16)));
}

#[test]
fn xbuttons_encode_identity_in_high_word_and_preserve_low_word_state() {
    let (mut state, id) = setup();
    state.post_compositor_pointer(id, 0, 0, (MK_XBUTTON1 | MK_XBUTTON2) as u32, 0, 0).unwrap();
    let messages = drain(&mut state, 11);
    assert_eq!((messages[1].message, messages[1].wparam), (WM_XBUTTONDOWN, MK_XBUTTON1 as u64 | ((XBUTTON1 as u64) << 16)));
    assert_eq!((messages[2].message, messages[2].wparam), (WM_XBUTTONDOWN, (MK_XBUTTON1 | MK_XBUTTON2) as u64 | ((XBUTTON2 as u64) << 16)));
    state.post_compositor_pointer(id, 0, 0, MK_XBUTTON2 as u32, 0, 0).unwrap();
    assert_eq!(drain(&mut state, 11)[0].wparam, MK_XBUTTON2 as u64 | ((XBUTTON1 as u64) << 16));
}

#[test]
fn capture_release_and_destroy_restore_source_routing() {
    let (mut state, source) = setup();
    let capture = state.create(22, None, 0).unwrap();
    state.set_capture(22, capture).unwrap();
    assert!(state.release_capture(22).unwrap());
    state.post_compositor_pointer(source, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(drain(&mut state, 11)[0].hwnd, Some(source));
    state.set_capture(22, capture).unwrap(); state.destroy(capture).unwrap();
    state.post_compositor_pointer(source, 2, 2, 0, 0, 0).unwrap();
    assert_eq!(drain(&mut state, 11)[0].hwnd, Some(source));
}

#[test]
fn full_queue_cannot_partially_publish_motion_buttons_or_wheel() {
    let (mut state, id) = setup();
    let message = WinMessage { hwnd: Some(id), message: WM_CLOSE, wparam: 0, lparam: 0 };
    for _ in 0..MESSAGE_QUEUE_LIMIT - 1 { state.post_to_window(id, message).unwrap(); }
    assert_eq!(state.post_compositor_pointer(id, 1, 2, MK_LBUTTON as u32, 120, 0), Err(WindowError::QueueFull));
    assert_eq!(state.cursor, (0, 0)); assert_eq!(state.buttons, 0);
    assert_eq!(drain(&mut state, 11).len(), MESSAGE_QUEUE_LIMIT - 1);
    state.post_compositor_pointer(id, 1, 2, MK_LBUTTON as u32, 120, 0).unwrap();
    assert_eq!(drain(&mut state, 11).len(), 3);
}

#[test]
fn malformed_pointer_and_stale_source_leave_canonical_state_unchanged() {
    let (mut state, id) = setup();
    for (x, buttons, wheel, hwheel) in [(i32::MAX, 0, 0, 0), (0, 1 << 8, 0, 0), (0, 0, 32768, 0), (0, 0, 0, 32768)] {
        assert_eq!(state.post_compositor_pointer(id, x, 0, buttons, wheel, hwheel), Err(WindowError::InvalidParent));
    }
    assert_eq!(state.cursor, (0, 0)); assert_eq!(state.buttons, 0);
    assert!(drain(&mut state, 11).is_empty());
    state.destroy(id).unwrap();
    assert_eq!(state.post_compositor_pointer(id, 0, 0, 0, 0, 0), Err(WindowError::NoSuchWindow));
}

/// A control's own X window reports a press in the control's coordinates, and
/// the control's canonical rectangle is stated in its parent's client space.
/// Adding one to the other names a point inside the parent, not on the screen:
/// every hit test the retrieval then runs answers for somewhere else and the
/// control is dead to the pointer.
#[test]
fn a_press_on_a_child_control_carries_the_screen_point_not_the_parent_relative_one() {
    let mut state = WindowManager::new();
    let parent = state.create(11, None, 0).unwrap();
    state.set_rect(parent, WindowRect { left: 100, top: 200, right: 400, bottom: 500 }).unwrap();
    state.set_client_rect(parent, WindowRect { left: 105, top: 230, right: 395, bottom: 495 }).unwrap();
    let child = state.create(11, Some(parent), 0).unwrap();
    state.set_rect(child, WindowRect { left: 10, top: 20, right: 60, bottom: 40 }).unwrap();
    state.post_compositor_pointer(child, 5, 7, MK_LBUTTON as u32, 0, 0).unwrap();
    let messages = drain(&mut state, 11);
    assert!(messages.iter().all(|message| message.hwnd == Some(parent)));
    assert_eq!(messages.iter().map(|message| (message.message, message.lparam)).collect::<Vec<_>>(), alloc::vec![
        (WM_MOUSEMOVE, mouse_lparam(120, 257)),
        (WM_LBUTTONDOWN, mouse_lparam(120, 257))]);
    assert_eq!(state.cursor, (120, 257));
}

/// Every ancestor between the control and the screen contributes its own
/// client origin, so a control nested inside a group box inside a dialog is
/// found at the sum and not at its immediate parent's offset.
#[test]
fn a_press_on_a_nested_control_accumulates_every_ancestor_client_origin() {
    let mut state = WindowManager::new();
    let dialog = state.create(11, None, 0).unwrap();
    state.set_rect(dialog, WindowRect { left: 145, top: 161, right: 891, bottom: 641 }).unwrap();
    state.set_client_rect(dialog, WindowRect { left: 148, top: 190, right: 888, bottom: 638 }).unwrap();
    let group = state.create(11, Some(dialog), 0).unwrap();
    state.set_rect(group, WindowRect { left: 12, top: 30, right: 300, bottom: 200 }).unwrap();
    let button = state.create(11, Some(group), 0).unwrap();
    state.set_rect(button, WindowRect { left: 20, top: 40, right: 100, bottom: 64 }).unwrap();
    state.post_compositor_pointer(button, 3, 4, 0, 0, 0).unwrap();
    let messages = drain(&mut state, 11);
    // 148+12+20+3 across, 190+30+40+4 down.
    assert_eq!(messages.iter().map(|message| (message.message, message.lparam)).collect::<Vec<_>>(),
        alloc::vec![(WM_MOUSEMOVE, mouse_lparam(183, 264))]);
}

#[test]
fn pointer_message_position_is_the_event_point_even_after_later_motion() {
    let (mut state, id) = setup();
    state.post_compositor_pointer(id, 10, 20, MK_LBUTTON as u32, 0, 0).unwrap();
    state.post_compositor_pointer(id, 30, 40, MK_LBUTTON as u32, 0, 0).unwrap();
    let filter = MessageFilter { hwnd: None, first: 0, last: 0 };
    for expected in [(110, 220), (110, 220), (130, 240)] {
        let message = state.peek_for_thread(11, filter, true).unwrap();
        assert_eq!(message.lparam as u32, msg_pos::pack_pos(expected.0, expected.1));
        assert_eq!(state.message_pos(11), msg_pos::pack_pos(expected.0, expected.1));
    }
}

#[test]
fn root_surface_input_queues_to_the_child_thread_without_narrowing_scope() {
    let (mut state, root) = setup();
    state.set_style_bits(root, styles::WS_VISIBLE, 0).unwrap();
    let child = state.create(22, Some(root), 0).unwrap();
    state.set_style_bits(child, styles::WS_VISIBLE | styles::WS_CHILD, 0).unwrap();
    state.set_rect(child, WindowRect { left: 10, top: 20, right: 80, bottom: 60 }).unwrap();
    state.post_compositor_pointer(root, 15, 25, MK_LBUTTON as u32, 0, 0).unwrap();
    assert!(drain(&mut state, 11).is_empty());
    let messages = drain(&mut state, 22);
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|message| message.hwnd == Some(root)));
    assert_eq!(messages[1].lparam, mouse_lparam(115, 225));
}

#[test]
fn queue_thread_lookup_precedes_the_disabled_scopes_hit_test() {
    let (mut state, root) = setup();
    state.set_style_bits(root, styles::WS_VISIBLE | styles::WS_DISABLED, 0).unwrap();
    let child = state.create(22, Some(root), 0).unwrap();
    state.set_style_bits(child, styles::WS_VISIBLE | styles::WS_CHILD, 0).unwrap();
    state.set_rect(child, WindowRect { left: 10, top: 20, right: 80, bottom: 60 }).unwrap();
    state.post_compositor_pointer(root, 15, 25, MK_LBUTTON as u32, 0, 0).unwrap();
    assert!(drain(&mut state, 11).is_empty());
    assert_eq!(drain(&mut state, 22).len(), 2);
}
