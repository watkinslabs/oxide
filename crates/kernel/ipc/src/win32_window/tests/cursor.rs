use super::*;
use crate::win32_window::{WindowError, WindowManager, OEM_CURSOR_BASE};

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

#[test]
fn a_builtin_cursor_carries_a_frame_and_the_arrow_points_from_its_corner() {
    let mut manager = WindowManager::new();
    let arrow = manager.shared_oem_cursor(IDC_ARROW).unwrap();
    let ibeam = manager.shared_oem_cursor(IDC_IBEAM).unwrap();
    let info = manager.icon_info(arrow).unwrap();
    assert!(!info.is_icon);
    assert_eq!((info.hotspot_x, info.hotspot_y), (0, 0));
    assert_eq!(manager.icon_info(ibeam).map(|info| (info.hotspot_x, info.hotspot_y)), Some((16, 16)));
    assert_eq!(manager.icon_size(arrow, 0), Some((32, 64)));
}

#[test]
fn the_show_count_hides_the_cursor_while_it_is_negative() {
    let mut manager = WindowManager::new();
    let arrow = manager.shared_oem_cursor(IDC_ARROW).unwrap();
    manager.set_current_cursor(arrow).unwrap();
    assert!(manager.cursor_showing());
    assert_eq!(manager.show_cursor(false), -1);
    assert!(!manager.cursor_showing());
    assert_eq!(manager.current_cursor(), 0);
    assert_eq!(manager.show_cursor(true), 0);
    assert_eq!(manager.current_cursor(), arrow);
}

#[test]
fn destroying_reports_whether_the_cursor_was_the_displayed_one_and_keeps_shared_objects() {
    let mut manager = WindowManager::new();
    let arrow = manager.shared_oem_cursor(IDC_ARROW).unwrap();
    assert!(manager.destroy_cursor(arrow));
    assert_eq!(manager.oem_cursor_id(arrow), Some(IDC_ARROW));
    manager.set_current_cursor(arrow).unwrap();
    assert!(!manager.destroy_cursor(arrow));
    assert!(!manager.destroy_cursor(0xdead));
}
