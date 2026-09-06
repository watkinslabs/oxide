use super::*;
use crate::win32_window::WindowManager;

#[test]
fn a_shared_oem_cursor_answers_one_handle_per_resource_id() {
    let mut manager = WindowManager::new();
    let arrow = manager.shared_oem_cursor(IDC_ARROW).unwrap();
    let ibeam = manager.shared_oem_cursor(IDC_IBEAM).unwrap();
    assert_eq!(manager.shared_oem_cursor(IDC_ARROW), Ok(arrow));
    assert_ne!(arrow, ibeam);
    assert!(arrow >= OEM_CURSOR_BASE && ibeam >= OEM_CURSOR_BASE);
    assert_eq!(manager.oem_cursor_id(arrow), Some(IDC_ARROW));
}

#[test]
fn an_unknown_resource_id_loads_no_cursor() {
    let mut manager = WindowManager::new();
    assert_eq!(manager.shared_oem_cursor(1), Err(WindowError::InvalidParent));
    assert_eq!(manager.oem_cursor_id(OEM_CURSOR_BASE), None);
}

#[test]
fn setting_the_displayed_cursor_answers_the_previous_one_and_refuses_a_stray_handle() {
    let mut manager = WindowManager::new();
    let arrow = manager.shared_oem_cursor(IDC_ARROW).unwrap();
    assert_eq!(manager.current_cursor(), 0);
    assert_eq!(manager.set_current_cursor(arrow), Ok(0));
    assert_eq!(manager.current_cursor(), arrow);
    assert_eq!(manager.set_current_cursor(0), Ok(arrow));
    assert_eq!(manager.set_current_cursor(0xdead), Err(WindowError::NoSuchWindow));
}
