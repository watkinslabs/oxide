use super::*;

#[test]
fn caret_lifecycle_is_thread_local_state() {
    let hwnd = WindowId::from_raw(7).unwrap();
    let mut caret = CaretState::new();
    caret.create(hwnd, 2, 16);
    assert!(!caret.visible());
    assert!(caret.set_pos(12, 19));
    assert!(caret.visible());
    assert!(caret.hide(hwnd));
    assert!(!caret.visible());
    assert!(caret.show(hwnd));
    assert!(caret.visible());
    caret.destroy();
    assert_eq!(caret.hwnd, None);
}
