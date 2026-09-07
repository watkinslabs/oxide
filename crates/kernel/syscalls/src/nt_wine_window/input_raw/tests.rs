use super::*;
use ipc::win32_window::{CursorPos, WindowRect};

const SCREEN: WindowRect = WindowRect { left: 0, top: 0, right: 1024, bottom: 768 };

#[test]
fn the_ordinals_match_the_generated_win32u_table() {
    assert_eq!([CLIP_CURSOR, GET_CLIP_CURSOR, GET_CURSOR_INFO, GET_CURSOR_POS, SET_CURSOR_POS,
        GET_MOUSE_MOVE_POINTS_EX, TRACK_MOUSE_EVENT, SET_CAPTURE, RELEASE_CAPTURE, GET_QUEUE_STATUS,
        GET_THREAD_STATE, GET_CURRENT_INPUT_MESSAGE_SOURCE, GET_DOUBLE_CLICK_TIME, REGISTER_HOTKEY,
        UNREGISTER_HOTKEY, ATTACH_THREAD_INPUT, SEND_INPUT, WAIT_FOR_INPUT_IDLE],
        [0x1350, 0x13da, 0x13e9, 0x13ea, 0x154a, 0x141f, 0x15d3, 0x153a, 0x1508, 0x143b,
         0x144e, 0x13e6, 0x13f5, 0x14f3, 0x15e0, 0x1322, 0x152e, 0x15f8]);
}

#[test]
fn a_rectangle_round_trips_through_the_client_record() {
    let rect = WindowRect { left: -3, top: 4, right: 100, bottom: 200 };
    assert_eq!(decode_rect(&encode_rect(rect)), rect);
}

#[test]
fn a_cursor_record_declares_its_size_and_reports_the_showing_flag() {
    let bytes = encode_cursor_info(0x1_0000, true, (7, 9));
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), CURSORINFO_BYTES as u32);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), CURSOR_SHOWING);
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0x1_0000);
    assert_eq!(i32::from_le_bytes(bytes[16..20].try_into().unwrap()), 7);
    assert_eq!(i32::from_le_bytes(bytes[20..24].try_into().unwrap()), 9);
    let hidden = encode_cursor_info(0, false, (0, 0));
    assert_eq!(u32::from_le_bytes(hidden[4..8].try_into().unwrap()), 0);
}

#[test]
fn a_move_point_carries_its_position_time_and_extra_word() {
    let bytes = encode_move_point(CursorPos { x: -1, y: 2, time: 30, info: 0xfeed });
    assert_eq!(i32::from_le_bytes(bytes[0..4].try_into().unwrap()), -1);
    assert_eq!(i32::from_le_bytes(bytes[4..8].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 30);
    assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 0xfeed);
}

#[test]
fn a_move_point_request_is_admitted_in_the_reference_order() {
    assert_eq!(check_move_points(0, 1, 1, 0, GMMP_USE_DISPLAY_POINTS), Err(MovePointError::InvalidParameter));
    let size = MOUSEMOVEPOINT_BYTES as u32;
    assert_eq!(check_move_points(size, 1, 1, -1, GMMP_USE_DISPLAY_POINTS), Err(MovePointError::InvalidParameter));
    assert_eq!(check_move_points(size, 1, 1, 65, GMMP_USE_DISPLAY_POINTS), Err(MovePointError::InvalidParameter));
    assert_eq!(check_move_points(size, 0, 1, 1, GMMP_USE_DISPLAY_POINTS), Err(MovePointError::NoAccess));
    assert_eq!(check_move_points(size, 1, 0, 1, GMMP_USE_DISPLAY_POINTS), Err(MovePointError::NoAccess));
    assert_eq!(check_move_points(size, 1, 0, 0, GMMP_USE_DISPLAY_POINTS), Ok(()));
    assert_eq!(check_move_points(size, 1, 1, 1, 2), Err(MovePointError::PointNotFound));
    assert_eq!(check_move_points(size, 1, 1, 64, GMMP_USE_DISPLAY_POINTS), Ok(()));
}

#[test]
fn an_injection_batch_must_declare_the_client_record_size_and_carry_records() {
    assert!(check_send_input(1, 0x1000, INPUT_BYTES));
    assert!(!check_send_input(1, 0x1000, INPUT_BYTES - 1));
    assert!(!check_send_input(0, 0x1000, INPUT_BYTES));
    assert!(!check_send_input(1, 0, INPUT_BYTES));
}

#[test]
fn an_absolute_injection_maps_onto_the_screen_rectangle() {
    assert_eq!(absolute_point(0, 0, SCREEN), (0, 0));
    assert_eq!(absolute_point(0xffff, 0xffff, SCREEN), (1023, 767));
    assert_eq!(absolute_point(0x8000, 0x8000, SCREEN), (512, 384));
    let offset = WindowRect { left: 100, top: 50, right: 356, bottom: 178 };
    assert_eq!(absolute_point(0, 0, offset), (100, 50));
}

#[test]
fn a_mouse_record_decodes_its_move_buttons_and_wheel_in_order() {
    let (steps, count) = mouse_steps(3, -4, 0, MOUSEEVENTF_MOVE, SCREEN);
    assert_eq!((count, steps[0]), (1, SendStep::MoveBy { dx: 3, dy: -4 }));
    let (steps, count) = mouse_steps(0x8000, 0x8000, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, SCREEN);
    assert_eq!((count, steps[0]), (1, SendStep::MoveTo { x: 512, y: 384 }));
    let flags = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP | MOUSEEVENTF_RIGHTDOWN;
    let (steps, count) = mouse_steps(0, 0, 0, flags, SCREEN);
    assert_eq!(count, 3);
    assert_eq!(steps[0], SendStep::Button { code: ipc::win32_window::BTN_LEFT, pressed: true });
    assert_eq!(steps[1], SendStep::Button { code: ipc::win32_window::BTN_LEFT, pressed: false });
    assert_eq!(steps[2], SendStep::Button { code: ipc::win32_window::BTN_RIGHT, pressed: true });
    let (steps, count) = mouse_steps(0, 0, (-240i32) as u32, MOUSEEVENTF_WHEEL, SCREEN);
    assert_eq!((count, steps[0]), (1, SendStep::Wheel { notches: -2 }));
    assert_eq!(mouse_steps(0, 0, 0, 0, SCREEN).1, 0);
}

#[test]
fn a_keyboard_record_decodes_its_transition() {
    assert_eq!(key_step(0x41, 0), SendStep::Key { vkey: 0x41, pressed: true });
    assert_eq!(key_step(0x41, KEYEVENTF_KEYUP), SendStep::Key { vkey: 0x41, pressed: false });
}
