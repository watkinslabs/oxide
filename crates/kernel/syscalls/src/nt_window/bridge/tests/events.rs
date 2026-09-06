use super::*;
use alloc::vec;

fn state() -> (WindowManager, WindowId) {
    let mut state = WindowManager::new();
    let id = state.create(17, None, 42).unwrap();
    state.set_rect(id, WindowRect { left: 20, top: 30, right: 220, bottom: 130 }).unwrap();
    (state, id)
}
fn event(opcode: Opcode, id: WindowId, payload: Vec<u8>) -> Record {
    Record::new(opcode, 1, id.raw() as u64, payload).unwrap()
}
fn words(values: &[u32]) -> Vec<u8> { values.iter().flat_map(|word| word.to_le_bytes()).collect() }
fn deliver(state: &mut WindowManager, event: &Record) -> bool {
    apply_event(state, event, |_, _, _, _, _, _| panic!("unexpected pointer"))
}
fn next(state: &mut WindowManager) -> Option<WinMessage> {
    state.peek_for_thread(17, gui::MessageFilter { hwnd: None, first: 0, last: 0 }, true)
}

#[test]
fn create_snapshot_copies_canonical_rect_parent_title_visibility() {
    let (mut state, parent) = state();
    let id = state.create(17, Some(parent), 43).unwrap();
    state.set_rect(id, WindowRect { left: -10, top: 12, right: 90, bottom: 62 }).unwrap();
    state.set_text(id, &"notes 🦀".encode_utf16().collect::<Vec<_>>()).unwrap();
    state.show(17, id, true).unwrap();
    let saved = snapshot(&state, id.raw() as u64).unwrap();
    state.set_text(id, &[b'X' as u16]).unwrap();
    assert_eq!(saved.title, "notes 🦀".as_bytes());
    assert!(saved.visible);
    let payload = saved.create_payload(0x1234, 0x4567).unwrap();
    let decoded = event(Opcode::Create, id, payload);
    assert_eq!(wire::Rect::decode(&decoded.payload[..16]).unwrap(), wire::Rect { x: -10, y: 12, width: 100, height: 50 });
    assert_eq!(wire::u64_at(&decoded.payload, 16), Ok(parent.raw() as u64));
    assert_eq!(wire::u32_at(&decoded.payload, 24), Ok(0x1234));
    assert_eq!(wire::u32_at(&decoded.payload, 28), Ok(0x4567));
}

#[test]
fn snapshots_reject_truncated_stale_and_unrepresentable_handles() {
    let (mut state, id) = state();
    assert!(snapshot(&state, (1u64 << 32) | id.raw() as u64).is_none());
    state.set_rect(id, WindowRect { left: i32::MIN, top: 0, right: i32::MAX, bottom: 1 }).unwrap();
    assert!(snapshot(&state, id.raw() as u64).is_none());
    state.destroy(id).unwrap();
    assert!(snapshot(&state, id.raw() as u64).is_none());
}

#[test]
fn owned_popup_snapshot_retains_transient_owner_without_child_parentage() {
    let (mut state, owner) = state();
    let popup = state.create(17, None, 43).unwrap();
    state.set_rect(popup, WindowRect { left: 0, top: 0, right: 30, bottom: 20 }).unwrap();
    state.set_window_styles(popup, 0x8000_0000, 0).unwrap();
    state.set_popup_owner(popup, Some(owner)).unwrap();
    assert_eq!(state.get(popup).unwrap().parent, None);
    let saved = snapshot(&state, popup.raw() as u64).unwrap();
    let payload = saved.create_payload(0x8000_0000, 0).unwrap();
    assert_eq!(wire::u64_at(&payload, 16), Ok(owner.raw() as u64));
    assert_eq!(wire::u32_at(&payload, 24), Ok(0x8000_0000));
}

#[test]
fn close_queues_request_without_destroy_or_quit() {
    let (mut state, id) = state();
    assert!(deliver(&mut state, &event(Opcode::Close, id, vec![])));
    assert!(state.get(id).is_some());
    assert!(!state.quit_pending(17));
    assert_eq!(next(&mut state), Some(WinMessage { hwnd: Some(id), message: gui::WM_CLOSE, wparam: 0, lparam: 0 }));
}

#[test]
fn configure_mutates_canonical_geometry_and_posts_move_size_paint() {
    let (mut state, id) = state();
    state.show(17, id, true).unwrap();
    state.begin_paint(id).unwrap(); state.end_paint(id).unwrap();
    let event = event(Opcode::Configure, id, words(&[40, 50, 300, 200]));
    assert!(deliver(&mut state, &event));
    assert_eq!(state.rect(id), Some(WindowRect { left: 40, top: 50, right: 340, bottom: 250 }));
    assert_eq!(next(&mut state).unwrap().message, WM_MOVE);
    let size = next(&mut state).unwrap();
    assert_eq!((size.message, size.lparam), (WM_SIZE, gui::mouse_lparam(300, 200)));
    assert_eq!(next(&mut state).unwrap().message, gui::WM_PAINT);
    state.begin_paint(id).unwrap(); state.end_paint(id).unwrap();
    assert!(deliver(&mut state, &event));
    assert_eq!(next(&mut state), None);
}

#[test]
fn key_scan_extended_repeat_release_and_alt_bits_are_preserved() {
    let (mut state, id) = state();
    assert!(deliver(&mut state, &event(Opcode::Key, id, words(&[0x41, 0x1e, 1, KEY_EXTENDED | KEY_PREVIOUS]))));
    let key = next(&mut state).unwrap();
    assert_eq!(key.message, gui::WM_KEYDOWN);
    assert_eq!(key.wparam, 0x41);
    assert_eq!(key.lparam as u32, 1 | (0x1e << 16) | KEY_EXTENDED | KEY_PREVIOUS);
    assert!(deliver(&mut state, &event(Opcode::Key, id, words(&[0x41, 0x1e, 0, KEY_ALT]))));
    let key = next(&mut state).unwrap();
    assert_eq!(key.message, WM_SYSKEYUP);
    assert_eq!(key.lparam as u32, 1 | (0x1e << 16) | KEY_ALT | KEY_PREVIOUS | KEY_RELEASE);
}

#[test]
fn raw_x11_key_fields_and_unknown_modifiers_are_rejected() {
    let (mut state, id) = state();
    for fields in [[0, 38, 1, 0], [0x100, 38, 1, 0], [0x41, 0x100, 1, 0], [0x41, 0x1e, 1, 8]] {
        assert!(!deliver(&mut state, &event(Opcode::Key, id, words(&fields))));
    }
    assert_eq!(next(&mut state), None);
}

#[test]
fn unicode_text_reaches_focused_child_as_utf16_surrogate_units() {
    let (mut state, id) = state();
    let child = state.create(17, Some(id), 43).unwrap();
    state.set_focus(17, Some(child)).unwrap();
    while next(&mut state).is_some() {}
    assert!(deliver(&mut state, &event(Opcode::Text, id, "A🦀".as_bytes().to_vec())));
    for unit in "A🦀".encode_utf16() {
        assert_eq!(next(&mut state), Some(WinMessage { hwnd: Some(child), message: WM_CHAR, wparam: unit as u64, lparam: 1 }));
    }
    assert_eq!(next(&mut state), None);
}

#[test]
fn unrelated_focus_does_not_steal_targeted_text() {
    let (mut state, id) = state();
    let unrelated = state.create(17, None, 43).unwrap();
    state.set_focus(17, Some(unrelated)).unwrap();
    while next(&mut state).is_some() {}
    assert!(deliver(&mut state, &event(Opcode::Text, id, vec![b'X'])));
    assert_eq!(next(&mut state).unwrap().hwnd, Some(id));
}

#[test]
fn malformed_and_stale_events_do_not_mutate_or_enqueue() {
    let (mut state, id) = state();
    let mut malformed = event(Opcode::Text, id, vec![b'X']);
    malformed.payload[0] = 0xff;
    assert!(!deliver(&mut state, &malformed));
    let mut wide = event(Opcode::Close, id, vec![]);
    wide.header.hwnd |= 1u64 << 32;
    assert!(!deliver(&mut state, &wide));
    assert!(!deliver(&mut state, &event(Opcode::Visibility, id, words(&[1]))));
    assert_eq!(next(&mut state), None);
    state.destroy(id).unwrap();
    assert!(!deliver(&mut state, &event(Opcode::Close, id, vec![])));
}

#[test]
fn pointer_forwards_absolute_signed_client_coordinates_and_win32_buttons_once() {
    let (mut state, id) = state();
    let record = event(Opcode::Pointer, id, words(&[-4i32 as u32, 12, gui::MK_LBUTTON as u32, -120i32 as u32]));
    let mut calls = 0;
    assert!(apply_event(&mut state, &record, |owner, target, x, y, buttons, wheel| {
        calls += 1;
        assert!(owner.get(target).is_some());
        assert_eq!((target, x, y, buttons, wheel), (id, -4, 12, 1, -120)); true
    }));
    assert_eq!(calls, 1);
}

#[test]
fn pointer_rejects_x11_button_mask_and_wheel_overflow_before_owner_call() {
    let (mut state, id) = state();
    for fields in [[0, 0, 1 << 8, 0], [0, 0, 0, 32768]] {
        assert!(!deliver(&mut state, &event(Opcode::Pointer, id, words(&fields))));
    }
}

#[test]
fn full_queue_failure_is_not_acknowledged_as_delivery() {
    let (mut state, id) = state();
    let msg = WinMessage { hwnd: Some(id), message: gui::WM_CLOSE, wparam: 0, lparam: 0 };
    while state.post_to_window(id, msg).is_ok() {}
    assert!(!deliver(&mut state, &event(Opcode::Close, id, vec![])));
}

#[test]
fn initial_updates_are_local_until_backend_creation_ack() {
    let mut state = WindowManager::new();
    let id = state.create(17, None, 0).unwrap();
    // Zero initial geometry is legal locally and must not be encoded before Create.
    assert_eq!(update_snapshot(&state, id.raw() as u64), Ok(None));
    state.set_text(id, &[65]).unwrap();
    state.set_rect(id, WindowRect { left: 1, top: 2, right: 101, bottom: 102 }).unwrap();
    assert_eq!(update_snapshot(&state, id.raw() as u64), Ok(None));
    state.set_presentation_ready(id, true).unwrap();
    assert_eq!(update_snapshot(&state, id.raw() as u64).unwrap().unwrap().title, b"A");
    state.set_presentation_ready(id, false).unwrap();
    assert_eq!(update_snapshot(&state, id.raw() as u64), Ok(None));
    state.destroy(id).unwrap();
    assert_eq!(update_snapshot(&state, id.raw() as u64), Err(()));
}

#[test]
fn bridge_pointer_reaches_canonical_capture_queue() {
    let (mut state, id) = state();
    let capture = state.create(17, None, 0).unwrap();
    state.set_rect(capture, WindowRect { left: 100, top: 200, right: 300, bottom: 400 }).unwrap();
    state.set_capture(17, capture).unwrap();
    let record = event(Opcode::Pointer, id, words(&[1, 2, gui::MK_LBUTTON as u32, 120]));
    assert!(apply_event(&mut state, &record, |state, id, x, y, buttons, wheel| {
        state.post_compositor_pointer(id, x, y, buttons, wheel).is_ok()
    }));
    let motion = next(&mut state).unwrap();
    assert_eq!((motion.hwnd, motion.message, motion.lparam), (Some(capture), gui::WM_MOUSEMOVE, gui::mouse_lparam(-79, -168)));
    assert_eq!(next(&mut state).unwrap().message, gui::WM_LBUTTONDOWN);
    let wheel = next(&mut state).unwrap();
    assert_eq!((wheel.message, wheel.lparam), (gui::WM_MOUSEWHEEL, gui::mouse_lparam(21, 32)));
}

#[test]
fn notepad_visible_statusbar_child_keeps_zero_geometry_and_main_parent() {
    const WS_CHILD: u32 = 0x4000_0000;
    const WS_VISIBLE: u32 = 0x1000_0000;
    let (mut state, main) = state();
    let edit = state.create(17, Some(main), 44).unwrap();
    let client = state.client_rect(main).unwrap();
    state.set_rect(edit, client).unwrap();
    let edit_snapshot = snapshot(&state, edit.raw() as u64).unwrap();
    assert_eq!(edit_snapshot.parent, main.raw() as u64);
    assert_eq!((edit_snapshot.rect.width, edit_snapshot.rect.height), (200, 100));
    let statusbar = state.create(17, Some(main), 43).unwrap();
    state.show(17, statusbar, true).unwrap();
    let initial = snapshot(&state, statusbar.raw() as u64).unwrap();
    assert!(initial.visible);
    assert_eq!(initial.rect, wire::Rect { x: 0, y: 0, width: 0, height: 0 });
    assert_eq!(initial.parent, main.raw() as u64);
    let create = event(Opcode::Create, statusbar, initial.create_payload(WS_VISIBLE | WS_CHILD, 0).unwrap());
    assert_eq!(wire::Rect::decode_window(&create.payload[..16]).unwrap(), initial.rect);
    assert_eq!(wire::u64_at(&create.payload, 16), Ok(main.raw() as u64));
    assert_eq!(wire::u32_at(&create.payload, 24), Ok(WS_VISIBLE | WS_CHILD));
    assert_eq!(next(&mut state), None);
    state.set_presentation_ready(statusbar, true).unwrap();
    let ready = update_snapshot(&state, statusbar.raw() as u64).unwrap().unwrap();
    assert_eq!(ready.rect.width, 0);
    assert_eq!(ready.rect.height, 0);
    assert!(ready.rect.validate().is_err());
    assert!(wire::pixel_len(0, 0, 0, wire::PIXEL_BGRA8888).is_err());
}

#[test]
fn configure_to_zero_updates_size_without_empty_region_paint_or_backing_size_echo() {
    let (mut state, main) = state();
    state.show(17, main, true).unwrap();
    state.begin_paint(main).unwrap(); state.end_paint(main).unwrap();
    let statusbar = state.create(17, Some(main), 43).unwrap();
    state.show(17, statusbar, true).unwrap();
    state.set_rect(statusbar, WindowRect { left: 0, top: 0, right: 200, bottom: 20 }).unwrap();
    assert!(deliver(&mut state, &event(Opcode::Configure, statusbar, words(&[0, 0, 0, 0]))));
    assert_eq!(state.rect(statusbar), Some(WindowRect { left: 0, top: 0, right: 0, bottom: 0 }));
    let size = next(&mut state).unwrap();
    assert_eq!((size.hwnd, size.message, size.lparam), (Some(statusbar), WM_SIZE, 0));
    assert_eq!(next(&mut state), None);
    assert!(deliver(&mut state, &event(Opcode::Configure, statusbar, words(&[0, 0, 200, 20]))));
    assert_eq!(next(&mut state).unwrap().message, WM_SIZE);
    assert_eq!(next(&mut state).unwrap().message, gui::WM_PAINT);
}

#[test]
fn window_geometry_accepts_each_zero_axis_but_rejects_negative_or_oversized_extents() {
    assert_eq!(wire_rect(WindowRect { left: 4, top: 5, right: 4, bottom: 25 }),
        Some(wire::Rect { x: 4, y: 5, width: 0, height: 20 }));
    assert_eq!(wire_rect(WindowRect { left: 4, top: 5, right: 24, bottom: 5 }),
        Some(wire::Rect { x: 4, y: 5, width: 20, height: 0 }));
    assert!(wire_rect(WindowRect { left: 4, top: 5, right: 3, bottom: 5 }).is_none());
    assert!(wire_rect(WindowRect { left: 0, top: 0, right: wire::MAX_DIMENSION as i32 + 1, bottom: 0 }).is_none());
}

fn fill_queue(state: &mut WindowManager, id: WindowId, spare: usize) {
    let msg = WinMessage { hwnd: Some(id), message: gui::WM_CLOSE, wparam: 0, lparam: 0 };
    while state.post_to_window(id, msg).is_ok() {}
    let owner = state.get(id).unwrap().owner_tid;
    for _ in 0..spare { state.peek_for_thread(owner, gui::MessageFilter { hwnd: None, first: 0, last: 0 }, true).unwrap(); }
}

#[test]
fn full_queue_text_rejects_entire_surrogate_pair_on_focused_child_owner() {
    let (mut state, main) = state();
    let child = state.create(23, Some(main), 0).unwrap();
    state.set_focus(23, Some(child)).unwrap();
    fill_queue(&mut state, child, 1);
    assert!(!deliver(&mut state, &event(Opcode::Text, main, "🦀".as_bytes().to_vec())));
    let filter = gui::MessageFilter { hwnd: None, first: WM_CHAR, last: WM_CHAR };
    assert_eq!(state.peek_for_thread(23, filter, true), None);
    assert!(state.check_message_capacity(child, 1).is_ok());
    assert!(state.check_message_capacity(child, 2).is_err());
    assert!(deliver(&mut state, &event(Opcode::Text, main, vec![b'X'])));
    assert_eq!(state.peek_for_thread(23, filter, true).unwrap().wparam, b'X' as u64);
}

#[test]
fn full_queue_configure_rejects_geometry_and_notifications_together() {
    let (mut state, id) = state();
    let original = state.rect(id);
    fill_queue(&mut state, id, 1);
    let configure = event(Opcode::Configure, id, words(&[40, 50, 300, 200]));
    assert!(!deliver(&mut state, &configure));
    assert_eq!(state.rect(id), original);
    let filter = gui::MessageFilter { hwnd: None, first: WM_MOVE, last: WM_SIZE };
    assert_eq!(state.peek_for_thread(17, filter, true), None);
    assert!(state.check_message_capacity(id, 1).is_ok());
    assert!(state.check_message_capacity(id, 2).is_err());
    next(&mut state).unwrap();
    assert!(deliver(&mut state, &configure));
    assert_eq!(state.rect(id), Some(WindowRect { left: 40, top: 50, right: 340, bottom: 250 }));
}

#[test]
fn configure_admission_counts_coalesced_paint_once() {
    let (mut state, id) = state();
    state.invalidate(id, None).unwrap();
    fill_queue(&mut state, id, 2);
    // Existing dirty state coalesces the repaint; only MOVE and SIZE require space.
    assert!(deliver(&mut state, &event(Opcode::Configure, id, words(&[40, 50, 300, 200]))));
    let filter = gui::MessageFilter { hwnd: None, first: WM_MOVE, last: WM_SIZE };
    assert_eq!(state.peek_for_thread(17, filter, true).unwrap().message, WM_MOVE);
    assert_eq!(state.peek_for_thread(17, filter, true).unwrap().message, WM_SIZE);
}

#[test]
fn bridge_key_and_text_deliver_one_character_and_canonical_control_state() {
    const VK_CONTROL: u32 = 0x11;
    const VK_LCONTROL: u32 = 0xa2;
    let (mut state, id) = state();
    assert!(deliver(&mut state, &event(Opcode::Key, id, words(&[VK_LCONTROL, 0x1d, 1, 0]))));
    assert_ne!(state.async_key_state(VK_LCONTROL as i32) as u16 & 0x8000, 0);
    assert_eq!(next(&mut state).unwrap().wparam, VK_CONTROL as u64);
    assert_ne!(state.key_state(17, VK_CONTROL as i32) as u16 & 0x8000, 0);
    assert!(deliver(&mut state, &event(Opcode::Key, id, words(&[0x41, 0x1e, 1, 0]))));
    assert!(deliver(&mut state, &event(Opcode::Text, id, vec![b'A'])));
    assert_eq!(next(&mut state).unwrap().message, gui::WM_KEYDOWN);
    let character = next(&mut state).unwrap();
    assert_eq!((character.message, character.wparam), (WM_CHAR, b'A' as u64));
    assert_eq!(next(&mut state), None);
    assert!(deliver(&mut state, &event(Opcode::Key, id, words(&[VK_LCONTROL, 0x1d, 0, 0]))));
    next(&mut state).unwrap();
    assert_eq!(state.key_state(17, VK_CONTROL as i32) as u16 & 0x8000, 0);
}

#[test]
fn creation_snapshot_publishes_canonical_styles_before_backend_readiness() {
    let (mut state, main) = state();
    let child = state.create(17, Some(main), 43).unwrap();
    let value = create_snapshot(&mut state, child.raw() as u64, 0x5000_0000, 0x200).unwrap();
    assert!(!value.ready);
    assert_eq!(state.window_styles(child), Some((0x5000_0000, 0x200)));
    assert_eq!((state.get(child).unwrap().style, state.get(child).unwrap().ex_style), (0x5000_0000, 0x200));
    assert_eq!((value.rect.width, value.rect.height), (0, 0));
}

#[test]
fn focused_child_on_another_thread_owns_key_text_and_message_time_control_state() {
    const CHILD_TID: u64 = 23;
    const VK_CONTROL: u32 = 0x11;
    let (mut state, main) = state();
    let child = state.create(CHILD_TID, Some(main), 0).unwrap();
    state.set_focus(CHILD_TID, Some(child)).unwrap();
    let any = gui::MessageFilter { hwnd: None, first: 0, last: 0 };
    while state.peek_for_thread(CHILD_TID, any, true).is_some() {}
    assert!(deliver(&mut state, &event(Opcode::Key, main, words(&[0xa2, 0x1d, 1, 0]))));
    assert!(deliver(&mut state, &event(Opcode::Text, main, "🦀".as_bytes().to_vec())));
    assert!(deliver(&mut state, &event(Opcode::Key, main, words(&[0xa2, 0x1d, 0, 0]))));
    assert_eq!(next(&mut state), None);
    let down = state.peek_for_thread(CHILD_TID, any, true).unwrap();
    assert_eq!((down.hwnd, down.message, down.wparam), (Some(child), gui::WM_KEYDOWN, VK_CONTROL as u64));
    assert_ne!(state.key_state(CHILD_TID, VK_CONTROL as i32) as u16 & 0x8000, 0);
    assert_eq!(state.key_state(17, VK_CONTROL as i32), 0);
    for unit in "🦀".encode_utf16() {
        let text = state.peek_for_thread(CHILD_TID, any, true).unwrap();
        assert_eq!((text.hwnd, text.message, text.wparam), (Some(child), WM_CHAR, unit as u64));
    }
    assert_eq!(state.peek_for_thread(CHILD_TID, any, true).unwrap().message, gui::WM_KEYUP);
    assert_eq!(state.key_state(CHILD_TID, VK_CONTROL as i32) as u16 & 0x8000, 0);
    assert_eq!(state.peek_for_thread(CHILD_TID, any, true), None);
}

#[test]
fn utf16_batch_rejects_entire_prefix_and_multiple_pairs_then_accepts_exact_capacity() {
    let (mut state, id) = state();
    let text = "A🦀𐐀";
    let count = text.encode_utf16().count();
    fill_queue(&mut state, id, count - 1);
    let record = event(Opcode::Text, id, text.as_bytes().to_vec());
    assert!(!deliver(&mut state, &record));
    let characters = gui::MessageFilter { hwnd: None, first: WM_CHAR, last: WM_CHAR };
    assert_eq!(state.peek_for_thread(17, characters, true), None);
    assert!(state.check_message_capacity(id, count - 1).is_ok());
    next(&mut state).unwrap();
    assert!(deliver(&mut state, &record));
    for unit in text.encode_utf16() { assert_eq!(state.peek_for_thread(17, characters, true).unwrap().wparam, unit as u64); }
    assert_eq!(state.peek_for_thread(17, characters, true), None);
}

#[test]
fn configure_move_only_uses_one_slot_and_unchanged_event_uses_none() {
    let (mut state, id) = state();
    fill_queue(&mut state, id, 1);
    let record = event(Opcode::Configure, id, words(&[40, 50, 200, 100]));
    assert!(deliver(&mut state, &record));
    assert!(state.check_message_capacity(id, 1).is_err());
    assert!(deliver(&mut state, &record));
    let notifications = gui::MessageFilter { hwnd: None, first: WM_MOVE, last: WM_SIZE };
    let moved = state.peek_for_thread(17, notifications, true).unwrap();
    assert_eq!((moved.message, moved.lparam), (WM_MOVE, gui::mouse_lparam(40, 50)));
    assert_eq!(state.peek_for_thread(17, notifications, true), None);
}

#[test]
fn configure_failure_preserves_existing_damage_as_well_as_rect_and_queue() {
    let (mut state, id) = state();
    let damage = WindowRect { left: 1, top: 2, right: 10, bottom: 20 };
    state.invalidate(id, Some(damage)).unwrap();
    let old = state.rect(id);
    fill_queue(&mut state, id, 1);
    assert!(!deliver(&mut state, &event(Opcode::Configure, id, words(&[40, 50, 300, 200]))));
    assert_eq!(state.rect(id), old);
    assert_eq!(state.begin_paint(id), Ok(Some(damage)));
    assert!(state.check_message_capacity(id, 1).is_ok());
}
