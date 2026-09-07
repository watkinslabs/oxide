use super::*;
use crate::win32_window::{MessageFilter, WindowManager};

const OWNER: u64 = 7;
const OTHER: u64 = 9;
const WM_CAPTURECHANGED: u32 = 0x0215;

fn manager() -> (WindowManager, crate::win32_window::WindowId, crate::win32_window::WindowId) {
    let mut manager = WindowManager::new();
    let first = manager.create(OWNER, None, 0).unwrap();
    let second = manager.create(OWNER, None, 0).unwrap();
    (manager, first, second)
}

#[test]
fn capture_installs_and_answers_the_previous_window() {
    let (mut manager, first, second) = manager();
    assert_eq!(manager.set_capture_window(OWNER, Some(first), 0), Ok(None));
    assert_eq!(manager.capture_window(), Some(first));
    assert_eq!(manager.set_capture_window(OWNER, Some(second), 0), Ok(Some(first)));
    let filter = MessageFilter { hwnd: Some(first), first: 0, last: 0 };
    let notified = manager.peek_for_thread(OWNER, filter, true).unwrap();
    assert_eq!(notified.message, WM_CAPTURECHANGED);
    assert_eq!(notified.lparam, second.raw() as i64);
}

#[test]
fn a_window_of_another_thread_cannot_take_the_capture_but_clearing_always_can() {
    let (mut manager, first, _) = manager();
    assert_eq!(manager.set_capture_window(OTHER, Some(first), 0), Err(crate::win32_window::WindowError::WrongThread));
    manager.set_capture_window(OWNER, Some(first), 0).unwrap();
    assert_eq!(manager.set_capture_window(OTHER, None, 0), Ok(Some(first)));
    assert_eq!(manager.capture_window(), None);
}

#[test]
fn a_menu_capture_is_only_replaced_by_another_menu_capture() {
    let (mut manager, first, second) = manager();
    manager.set_capture_window(OWNER, Some(first), CAPTURE_MENU).unwrap();
    assert_eq!(manager.menu_owner(), Some(first));
    assert_eq!(manager.set_capture_window(OWNER, Some(second), 0), Err(crate::win32_window::WindowError::WrongThread));
    assert_eq!(manager.set_capture_window(OWNER, Some(second), CAPTURE_MENU), Ok(Some(first)));
}

#[test]
fn the_move_size_role_follows_only_a_request_that_claims_it() {
    let (mut manager, first, _) = manager();
    manager.set_capture_window(OWNER, Some(first), CAPTURE_MOVESIZE).unwrap();
    assert_eq!(manager.move_size_window(), Some(first));
    manager.set_capture_window(OWNER, None, 0).unwrap();
    assert_eq!(manager.move_size_window(), None);
}

#[test]
fn an_unknown_window_is_refused() {
    let mut manager = WindowManager::new();
    let stray = crate::win32_window::WindowId::from_raw(0x1234).unwrap();
    assert_eq!(manager.set_capture_window(OWNER, Some(stray), 0), Err(crate::win32_window::WindowError::NoSuchWindow));
}
