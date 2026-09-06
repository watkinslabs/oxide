use super::*;
use crate::win32_window::WindowManager;

#[test]
fn caret_lifecycle_is_thread_local_state() {
    let hwnd = WindowId::from_raw(7).unwrap();
    let mut caret = CaretState::new();
    caret.create(hwnd, 2, 16);
    assert!(!caret.visible());
    assert!(caret.set_pos(12, 19).is_some());
    assert!(!caret.visible());
    assert!(caret.show(Some(hwnd)).is_some());
    assert!(caret.visible());
    assert!(caret.hide(None).is_some());
    assert!(!caret.visible());
    assert!(caret.show(None).is_some());
    assert!(caret.visible());
    caret.destroy();
    assert_eq!(caret.hwnd, None);
}

#[test]
fn recreating_same_window_retains_position_but_stays_hidden() {
    let hwnd = WindowId::from_raw(8).unwrap();
    let mut caret = CaretState::new();
    caret.create(hwnd, 2, 16);
    caret.set_pos(12, 19);
    caret.show(Some(hwnd));
    caret.create(hwnd, 4, 20);
    assert_eq!((caret.x, caret.y, caret.width, caret.height), (12, 19, 4, 20));
    assert_eq!(caret.hide_depth, 1);
    assert!(!caret.visible());
}

#[test]
fn owner_queue_enforces_tid_and_null_show_hide_targets_current_caret() {
    let mut manager = WindowManager::new();
    let hwnd = manager.create(7, None, 0).unwrap();
    manager.create_caret(7, hwnd, 2, 16).unwrap();
    manager.set_caret_pos(7, 12, 19).unwrap();
    assert!(manager.show_caret(7, None).unwrap().transition.new_visible);
    assert!(manager.hide_caret(7, None).is_ok());
    assert_eq!(manager.show_caret(8, Some(hwnd)), Err(CaretError::WrongThread));
    manager.destroy(hwnd).unwrap();
    assert_eq!(manager.show_caret(7, None), Err(CaretError::NoCaret));
}
