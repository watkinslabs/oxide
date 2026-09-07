use super::*;
use crate::win32_window::{WinMessage, WindowManager, WindowRect};

const TID: u64 = 5;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_KEYDOWN: u32 = 0x0100;
const WM_USER: u32 = 0x0400;

#[test]
fn the_hardware_classification_matches_the_message_ranges() {
    assert_eq!(hardware_bit(WM_MOUSEMOVE), QS_MOUSEMOVE);
    assert_eq!(hardware_bit(0x00a0), QS_MOUSEMOVE);
    assert_eq!(hardware_bit(WM_KEYDOWN), QS_KEY);
    assert_eq!(hardware_bit(0x0109), QS_KEY);
    assert_eq!(hardware_bit(0x00ff), QS_RAWINPUT);
    assert_eq!(hardware_bit(0x0246), QS_POINTER);
    assert_eq!(hardware_bit(WM_LBUTTONDOWN), QS_MOUSEBUTTON);
}

#[test]
fn the_result_packs_changed_low_and_wake_high_masked_by_the_request() {
    let packed = queue_status_result(QS_KEY | QS_TIMER, QS_KEY | QS_PAINT, QS_KEY | QS_PAINT);
    assert_eq!(packed & 0xffff, QS_KEY);
    assert_eq!(packed >> 16, QS_KEY | QS_PAINT);
}

#[test]
fn a_posted_message_wakes_the_post_bits_and_the_query_clears_only_what_it_reports() {
    let mut manager = WindowManager::new();
    let window = manager.create(TID, None, 0).unwrap();
    manager.post_to_window(window, WinMessage { hwnd: Some(window), message: WM_USER, wparam: 0, lparam: 0 }).unwrap();
    let first = manager.queue_status(TID, QS_ALLINPUT).unwrap();
    assert_eq!(first & 0xffff & QS_POSTMESSAGE, QS_POSTMESSAGE);
    let second = manager.queue_status(TID, QS_ALLINPUT).unwrap();
    assert_eq!(second & 0xffff & QS_POSTMESSAGE, 0);
    assert_eq!((second >> 16) & QS_POSTMESSAGE, QS_POSTMESSAGE);
}

#[test]
fn hardware_pointer_input_wakes_the_mouse_bits_not_the_post_bits() {
    let mut manager = WindowManager::new();
    let window = manager.create(TID, None, 0).unwrap();
    manager.set_rect(window, WindowRect { left: 0, top: 0, right: 100, bottom: 100 }).unwrap();
    manager.post_compositor_pointer(window, 5, 5, 0, 0).unwrap();
    let status = manager.queue_status(TID, QS_ALLINPUT).unwrap();
    assert_eq!((status >> 16) & QS_MOUSEMOVE, QS_MOUSEMOVE);
    assert_eq!((status >> 16) & QS_POSTMESSAGE, 0);
    assert_eq!(manager.input_state(TID), 0);
}

#[test]
fn flags_outside_the_admitted_set_answer_nothing() {
    let mut manager = WindowManager::new();
    assert_eq!(manager.queue_status(TID, 0x2000), None);
    assert_eq!(manager.queue_status(TID, QS_SMRESULT), Some(0));
}

#[test]
fn the_thread_state_classes_decode_in_order() {
    assert_eq!(thread_state(0), Some(ThreadState::FocusWindow));
    assert_eq!(thread_state(2), Some(ThreadState::CaptureWindow));
    assert_eq!(thread_state(6), Some(ThreadState::Cursor));
    assert_eq!(thread_state(10), Some(ThreadState::IsForeground));
    assert_eq!(thread_state(11), None);
}
