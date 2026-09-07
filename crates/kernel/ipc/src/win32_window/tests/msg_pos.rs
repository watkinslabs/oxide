//! Message position and extra information: packing, what a retrieval records,
//! and what a set replaces.
use super::*;
use crate::win32_window::{MessageFilter, WinMessage, WindowManager, WindowRect};

const SCREEN: WindowRect = WindowRect { left: 0, top: 0, right: 1024, bottom: 768 };

#[test]
fn packing_puts_x_low_and_y_high_and_round_trips_signed_coordinates() {
    assert_eq!(pack_pos(0x1234, 0x5678), 0x5678_1234);
    assert_eq!(pos_x(pack_pos(-3, 7)), -3);
    assert_eq!(pos_y(pack_pos(-3, 7)), 7);
    // Coordinates outside the signed 16-bit range truncate, as the packed
    // position has only sixteen bits per axis.
    assert_eq!(pos_x(pack_pos(0x1_0005, 0)), 5);
}

fn manager_with_window() -> (WindowManager, crate::win32_window::WindowId) {
    let mut state = WindowManager::new();
    let window = state.create(1, None, 0).unwrap();
    (state, window)
}

const ALL: MessageFilter = MessageFilter { hwnd: None, first: 0, last: u32::MAX };

#[test]
fn a_retrieval_reports_the_cursor_position_of_the_moment_the_message_was_queued() {
    let (mut state, window) = manager_with_window();
    state.set_cursor_pos(11, 22, SCREEN, 0);
    state.post_to_window(window, WinMessage { hwnd: Some(window), message: 0x0400, wparam: 0, lparam: 0 }).unwrap();
    // Moving the cursor after the post must not change what the retrieval reports.
    state.set_cursor_pos(900, 900, SCREEN, 0);
    assert_eq!(state.message_pos(1), 0);
    assert!(state.peek_for_thread(1, ALL, true).is_some());
    assert_eq!((pos_x(state.message_pos(1)), pos_y(state.message_pos(1))), (11, 22));
}

#[test]
fn a_thread_that_has_read_no_message_and_a_thread_with_no_queue_report_the_origin() {
    let (state, _) = manager_with_window();
    assert_eq!(state.message_pos(1), 0);
    assert_eq!(state.message_pos(999), 0);
}

#[test]
fn setting_extra_information_reports_the_value_it_replaced_and_a_retrieval_resets_it() {
    let (mut state, window) = manager_with_window();
    assert_eq!(state.set_message_extra(1, 0x1234_5678), 0);
    assert_eq!(state.set_message_extra(1, -9), 0x1234_5678);
    assert_eq!(state.message_extra(1), -9);
    state.post_to_window(window, WinMessage { hwnd: Some(window), message: 0x0400, wparam: 0, lparam: 0 }).unwrap();
    assert!(state.peek_for_thread(1, ALL, true).is_some());
    assert_eq!(state.message_extra(1), 0);
}

#[test]
fn a_thread_with_no_queue_yet_keeps_the_extra_information_it_sets() {
    let mut state = WindowManager::new();
    assert_eq!(state.set_message_extra(7, 5), 0);
    assert_eq!(state.message_extra(7), 5);
}
