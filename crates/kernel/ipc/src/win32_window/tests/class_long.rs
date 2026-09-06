use super::*;
use crate::win32_window::{ClassRegistration, WindowManager};

fn manager() -> (WindowManager, super::super::WindowId, u16) {
    let mut manager = WindowManager::new();
    let name = [b'E' as u16, b'd' as u16, b'i' as u16, b't' as u16];
    let atom = manager.register_class_desc(ClassRegistration {
        cb_cls_extra: 8, cb_wnd_extra: 6, style: 0x0008, background: 5, cursor: 0x1_0001, icon: 7, icon_sm: 9, module: 0x4000,
        ..ClassRegistration::new(&name, 0xdead_beef) }).unwrap();
    let window = manager.create_class_atom(1, None, atom).unwrap();
    (manager, window, atom)
}

#[test]
fn every_negative_class_offset_reads_its_own_field() {
    let (manager, window, atom) = manager();
    assert_eq!(manager.class_long(window, GCW_ATOM, 2), Ok(atom as u64));
    assert_eq!(manager.class_long(window, GCL_STYLE, 4), Ok(0x0008));
    assert_eq!(manager.class_long(window, GCL_CBWNDEXTRA, 4), Ok(6));
    assert_eq!(manager.class_long(window, GCL_CBCLSEXTRA, 4), Ok(8));
    assert_eq!(manager.class_long(window, GCLP_HMODULE, 8), Ok(0x4000));
    assert_eq!(manager.class_long(window, GCLP_HBRBACKGROUND, 8), Ok(5));
    assert_eq!(manager.class_long(window, GCLP_HCURSOR, 8), Ok(0x1_0001));
    assert_eq!(manager.class_long(window, GCLP_HICON, 8), Ok(7));
    assert_eq!(manager.class_long(window, GCLP_HICONSM, 8), Ok(9));
    assert_eq!(manager.class_long(window, GCLP_WNDPROC, 8), Ok(0xdead_beef));
    assert_eq!(manager.class_long(window, GCL_MENUNAME, 8), Ok(0));
}

#[test]
fn a_class_long_is_truncated_to_the_requested_width() {
    let (manager, window, _) = manager();
    assert_eq!(manager.class_long(window, GCLP_WNDPROC, 4), Ok(0xdead_beef));
    assert_eq!(manager.class_long(window, GCLP_WNDPROC, 2), Ok(0xbeef));
}

#[test]
fn setting_a_class_long_answers_the_previous_value_and_is_seen_by_every_window() {
    let (mut manager, window, atom) = manager();
    let sibling = manager.create_class_atom(1, None, atom).unwrap();
    assert_eq!(manager.set_class_long(window, GCLP_HCURSOR, 0x1_0002, 8), Ok(0x1_0001));
    assert_eq!(manager.class_long(sibling, GCLP_HCURSOR, 8), Ok(0x1_0002));
}

#[test]
fn the_class_extra_size_cannot_be_changed_and_a_stray_offset_is_rejected() {
    let (mut manager, window, _) = manager();
    assert_eq!(manager.set_class_long(window, GCL_CBCLSEXTRA, 16, 4), Err(LongPtrError::InvalidSize));
    assert_eq!(manager.class_long(window, 8, 4), Err(LongPtrError::InvalidIndex));
    assert_eq!(manager.class_long(window, 0, 3), Err(LongPtrError::InvalidSize));
}

#[test]
fn class_extra_bytes_round_trip_at_a_non_negative_offset() {
    let (mut manager, window, _) = manager();
    assert_eq!(manager.set_class_long(window, 0, 0x1122_3344, 4), Ok(0));
    assert_eq!(manager.class_long(window, 0, 4), Ok(0x1122_3344));
    assert_eq!(manager.class_long(window, 2, 2), Ok(0x1122));
}

#[test]
fn a_window_with_no_class_has_no_class_long() {
    let mut manager = WindowManager::new();
    let window = manager.create(1, None, 0).unwrap();
    assert_eq!(manager.class_long(window, GCLP_HCURSOR, 8), Err(LongPtrError::InvalidWindow));
}
