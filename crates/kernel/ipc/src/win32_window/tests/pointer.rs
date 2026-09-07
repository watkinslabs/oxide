//! Pointer records: what a pointer message names, which record size each
//! pointer type reports in, and what the per-thread table answers.
use super::*;
use crate::win32_window::{MessageFilter, WinMessage, WindowManager};

#[test]
fn record_sizes_match_the_client_abi_and_only_enumerated_types_name_one() {
    assert_eq!(POINTER_INFO_BYTES, 96);
    assert_eq!(POINTER_PEN_INFO_BYTES, 120);
    assert_eq!(POINTER_TOUCH_INFO_BYTES, 144);
    assert_eq!(info_record_bytes(PT_POINTER), Some(POINTER_INFO_BYTES));
    assert_eq!(info_record_bytes(PT_PEN), Some(POINTER_PEN_INFO_BYTES));
    assert_eq!(info_record_bytes(PT_MOUSE), Some(POINTER_PEN_INFO_BYTES));
    assert_eq!(info_record_bytes(PT_TOUCH), Some(POINTER_TOUCH_INFO_BYTES));
    assert_eq!(info_record_bytes(PT_TOUCHPAD), Some(POINTER_TOUCH_INFO_BYTES));
    assert_eq!(info_record_bytes(0), None);
    assert_eq!(info_record_bytes(6), None);
}

#[test]
fn the_information_list_refuses_the_mouse_type_and_every_mismatched_size() {
    assert!(!info_list_admitted(PT_MOUSE, POINTER_PEN_INFO_BYTES as u64));
    assert!(info_list_admitted(PT_POINTER, POINTER_INFO_BYTES as u64));
    assert!(!info_list_admitted(PT_POINTER, POINTER_INFO_BYTES as u64 - 1));
    assert!(info_list_admitted(PT_TOUCH, POINTER_TOUCH_INFO_BYTES as u64));
    assert!(!info_list_admitted(PT_TOUCH, POINTER_INFO_BYTES as u64));
    assert!(!info_list_admitted(0, POINTER_INFO_BYTES as u64));
}

#[test]
fn a_message_names_its_pointer_in_the_low_half_and_its_flags_in_the_high_half() {
    let wparam = (u64::from(POINTER_FLAG_INRANGE as u16) << 16) | 42;
    assert_eq!(pointer_id_of(wparam), 42);
    assert_eq!(pointer_flags_of(WM_POINTERUPDATE, wparam), POINTER_FLAG_INRANGE | POINTER_FLAG_UPDATE);
    assert_eq!(pointer_flags_of(WM_POINTERDOWN, wparam), POINTER_FLAG_INRANGE | POINTER_FLAG_DOWN);
    assert_eq!(pointer_flags_of(WM_POINTERUP, wparam), POINTER_FLAG_INRANGE | POINTER_FLAG_UP);
    assert_eq!(pointer_flags_of(WM_POINTERLEAVE, wparam), POINTER_FLAG_INRANGE);
}

#[test]
fn a_button_that_goes_down_and_one_that_comes_up_report_their_own_changes() {
    assert_eq!(button_change(0, POINTER_FLAG_FIRSTBUTTON), POINTER_CHANGE_FIRSTBUTTON_DOWN);
    assert_eq!(button_change(POINTER_FLAG_FIRSTBUTTON, 0), POINTER_CHANGE_FIRSTBUTTON_UP);
    assert_eq!(button_change(POINTER_FLAG_SECONDBUTTON, POINTER_FLAG_SECONDBUTTON), POINTER_CHANGE_NONE);
    assert_eq!(button_change(0, POINTER_FLAG_THIRDBUTTON), POINTER_CHANGE_THIRDBUTTON_DOWN);
    assert_eq!(button_change(0, POINTER_FLAG_FIFTHBUTTON), POINTER_CHANGE_FIFTHBUTTON_DOWN);
}

#[test]
fn the_himetric_location_scales_pixels_by_the_dots_per_inch_and_a_missing_scale_answers_the_origin() {
    assert_eq!(himetric_of(96, 96), HIMETRIC_PER_INCH);
    assert_eq!(himetric_of(0, 96), 0);
    assert_eq!(himetric_of(96, 0), 0);
    assert_eq!(himetric_of(96, -1), 0);
}

const ALL: MessageFilter = MessageFilter { hwnd: None, first: 0, last: u32::MAX };

#[test]
fn the_mouse_identity_answers_the_mouse_type_before_any_pointer_message() {
    let state = WindowManager::new();
    assert_eq!(state.pointer_type(1, MOUSE_POINTER_ID), Some(PT_MOUSE));
    assert_eq!(state.pointer_type(1, 0), None);
    assert_eq!(state.pointer_type(1, 7), None);
}

#[test]
fn retrieving_a_pointer_message_creates_the_record_a_later_query_reads() {
    let mut state = WindowManager::new();
    let window = state.create(1, None, 0).unwrap();
    let wparam = (u64::from(POINTER_FLAG_INRANGE as u16) << 16) | 7;
    state.post_to_window(window, WinMessage { hwnd: Some(window), message: WM_POINTERDOWN, wparam,
        lparam: crate::win32_window::mouse_lparam(30, 40) }).unwrap();
    assert_eq!(state.pointer_type(1, 7), None);
    assert!(state.peek_for_thread(1, ALL, true).is_some());
    assert_eq!(state.pointer_type(1, 7), Some(PT_POINTER));
    let info = state.pointer_info(1, 7).expect("the retrieval must have created the record");
    assert_eq!(info.id, 7);
    assert_eq!(info.pixel, (30, 40));
    assert_eq!(info.flags, POINTER_FLAG_INRANGE | POINTER_FLAG_DOWN);
    assert_eq!(info.history, 1);
    assert_eq!(info.target, window.raw());
    assert_eq!(info.source_device, NO_SOURCE_DEVICE);
}

#[test]
fn a_second_pointer_message_refreshes_the_record_and_reports_the_button_that_changed() {
    let mut state = WindowManager::new();
    let window = state.create(1, None, 0).unwrap();
    let down = (u64::from(POINTER_FLAG_FIRSTBUTTON as u16) << 16) | 9;
    state.post_to_window(window, WinMessage { hwnd: Some(window), message: WM_POINTERDOWN, wparam: down, lparam: 0 }).unwrap();
    assert!(state.peek_for_thread(1, ALL, true).is_some());
    assert_eq!(state.pointer_info(1, 9).unwrap().button_change, POINTER_CHANGE_FIRSTBUTTON_DOWN);
    state.post_to_window(window, WinMessage { hwnd: Some(window), message: WM_POINTERUP, wparam: 9, lparam: 0 }).unwrap();
    assert!(state.peek_for_thread(1, ALL, true).is_some());
    let info = state.pointer_info(1, 9).unwrap();
    assert_eq!(info.button_change, POINTER_CHANGE_FIRSTBUTTON_UP);
    assert_eq!(info.flags, POINTER_FLAG_UP);
    // The frame identity advances with every refreshed record.
    assert_eq!(info.frame, 2);
}

#[test]
fn a_message_that_is_not_a_pointer_message_creates_no_record() {
    let mut state = WindowManager::new();
    let window = state.create(1, None, 0).unwrap();
    state.post_to_window(window, WinMessage { hwnd: Some(window), message: 0x0400, wparam: 7, lparam: 0 }).unwrap();
    assert!(state.peek_for_thread(1, ALL, true).is_some());
    assert_eq!(state.pointer_type(1, 7), None);
}
