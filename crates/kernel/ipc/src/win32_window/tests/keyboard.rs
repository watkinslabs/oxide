use super::*;
const VK_CAPITAL: u8 = 0x14;
fn setup() -> (WindowManager, WindowId) {
    let mut state = WindowManager::new(); let id = state.create(11, None, 0).unwrap(); (state, id)
}
fn key(state: &mut WindowManager, id: WindowId, key: u8, pressed: bool) -> Result<(), WindowError> {
    state.post_compositor_key(id, WinMessage { hwnd: Some(id), message: if pressed { WM_KEYDOWN } else { WM_KEYUP },
        wparam: key as u64, lparam: 1 })
}
fn next(state: &mut WindowManager) -> Option<WinMessage> {
    state.peek_for_thread(11, MessageFilter { hwnd: None, first: 0, last: 0 }, true)
}

#[test]
fn control_state_tracks_consumed_keydown_before_already_queued_release() {
    let (mut state, id) = setup();
    key(&mut state, id, VK_LCONTROL, true).unwrap();
    key(&mut state, id, VK_LCONTROL, false).unwrap();
    assert_eq!(state.async_key_state(VK_LCONTROL as i32), 1);
    assert_eq!(state.async_key_state(VK_LCONTROL as i32), 0);
    assert_eq!(state.key_state(11, VK_CONTROL as i32), 0);
    assert_eq!(next(&mut state).unwrap().wparam, VK_CONTROL as u64);
    assert_ne!(state.key_state(11, VK_CONTROL as i32) as u16 & 0x8000, 0);
    assert_ne!(state.keyboard_state(11)[VK_LCONTROL as usize] & DOWN, 0);
    next(&mut state).unwrap();
    assert_eq!(state.key_state(11, VK_CONTROL as i32) as u16 & 0x8000, 0);
}

#[test]
fn both_shift_sides_keep_generic_down_until_last_release() {
    let (mut state, id) = setup();
    for (keycode, pressed) in [(VK_LSHIFT, true), (VK_RSHIFT, true), (VK_LSHIFT, false)] {
        key(&mut state, id, keycode, pressed).unwrap(); next(&mut state).unwrap();
        assert_ne!(state.key_state(11, VK_SHIFT as i32) as u16 & 0x8000, 0);
    }
    key(&mut state, id, VK_RSHIFT, false).unwrap(); next(&mut state).unwrap();
    assert_eq!(state.key_state(11, VK_SHIFT as i32) as u16 & 0x8000, 0);
}

#[test]
fn toggle_changes_on_new_press_not_repeat_or_release() {
    let (mut state, id) = setup();
    for (pressed, expected) in [(true, 0x81), (true, 0x81), (false, 1), (true, 0x80), (false, 0)] {
        key(&mut state, id, VK_CAPITAL, pressed).unwrap(); next(&mut state).unwrap();
        assert_eq!(state.keyboard_state(11)[VK_CAPITAL as usize], expected);
    }
}

#[test]
fn peek_without_remove_and_posted_key_messages_do_not_advance_input_state() {
    let (mut state, id) = setup();
    let filter = MessageFilter { hwnd: None, first: 0, last: 0 };
    key(&mut state, id, VK_LCONTROL, true).unwrap();
    assert!(state.peek_for_thread(11, filter, false).is_some());
    assert_eq!(state.key_state(11, VK_CONTROL as i32), 0);
    next(&mut state).unwrap();
    state.post_to_window(id, WinMessage { hwnd: Some(id), message: WM_KEYUP, wparam: VK_LCONTROL as u64, lparam: 1 }).unwrap();
    next(&mut state).unwrap();
    assert_ne!(state.key_state(11, VK_CONTROL as i32) as u16 & 0x8000, 0);
}

#[test]
fn queue_full_does_not_change_async_or_synchronous_key_state() {
    let (mut state, id) = setup();
    let message = WinMessage { hwnd: Some(id), message: WM_CLOSE, wparam: 0, lparam: 0 };
    while state.post_to_window(id, message).is_ok() {}
    assert_eq!(key(&mut state, id, VK_LCONTROL, true), Err(WindowError::QueueFull));
    assert_eq!(state.async_key_state(VK_LCONTROL as i32), 0);
    assert_eq!(state.key_state(11, VK_CONTROL as i32), 0);
    assert_eq!(state.keyboard_state(11), [0; KEY_COUNT]);
}

#[test]
fn keyboard_override_is_thread_local_masked_and_not_physical() {
    let (mut state, _) = setup();
    let mut bytes = [0; KEY_COUNT]; bytes[VK_CONTROL as usize] = 0xff;
    state.set_keyboard_state(11, &bytes);
    assert_eq!(state.key_state(11, VK_CONTROL as i32), -127);
    assert_eq!(state.keyboard_state(11)[VK_CONTROL as usize], 0x81);
    assert_eq!(state.keyboard_state(22), [0; KEY_COUNT]);
    assert_eq!(state.async_key_state(VK_CONTROL as i32), 0);
    assert_eq!(state.async_key_state(-1), 0);
    assert_eq!(state.async_key_state(256), 0);
}

#[test]
fn queue_full_release_preserves_accepted_down_state() {
    let (mut state, id) = setup();
    key(&mut state, id, VK_LCONTROL, true).unwrap(); next(&mut state).unwrap();
    let message = WinMessage { hwnd: Some(id), message: WM_CLOSE, wparam: 0, lparam: 0 };
    while state.post_to_window(id, message).is_ok() {}
    assert_eq!(key(&mut state, id, VK_LCONTROL, false), Err(WindowError::QueueFull));
    assert_ne!(state.async_key_state(VK_LCONTROL as i32) as u16 & 0x8000, 0);
    assert_ne!(state.key_state(11, VK_CONTROL as i32) as u16 & 0x8000, 0);
}

#[test]
fn generic_modifier_uses_scan_and_extended_bit_for_sided_state() {
    let (mut state, id) = setup();
    for (vk, scan, flags, side) in [(VK_CONTROL, 0x1d, EXTENDED, VK_RCONTROL), (VK_SHIFT, RIGHT_SHIFT_SCAN, 0, VK_RSHIFT)] {
        state.post_compositor_key(id, WinMessage { hwnd: Some(id), message: WM_KEYDOWN, wparam: vk as u64,
            lparam: (1 | ((scan as u32) << 16) | flags) as i64 }).unwrap();
        next(&mut state).unwrap();
        assert_ne!(state.key_state(11, side as i32) as u16 & 0x8000, 0);
    }
}
