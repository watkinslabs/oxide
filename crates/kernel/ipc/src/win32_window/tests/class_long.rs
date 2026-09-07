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

#[test]
fn the_class_extra_block_is_shared_by_every_window_of_the_class() {
    let (mut manager, window, atom) = manager();
    let sibling = manager.create_class_atom(1, None, atom).unwrap();
    assert_eq!(manager.set_class_long(window, 4, 0x5566_7788, 4), Ok(0));
    assert_eq!(manager.class_long(sibling, 4, 4), Ok(0x5566_7788));
    // Positive control: a window of another class reads its own block.
    let other = [b'O' as u16];
    let second = manager.register_class_desc(ClassRegistration { cb_cls_extra: 8, ..ClassRegistration::new(&other, 1) }).unwrap();
    let stranger = manager.create_class_atom(1, None, second).unwrap();
    assert_eq!(manager.class_long(stranger, 4, 4), Ok(0));
}

#[test]
fn an_offset_past_the_class_extra_block_is_refused() {
    let (mut manager, window, _) = manager();
    assert_eq!(manager.class_long(window, 4, 8), Err(LongPtrError::InvalidIndex));
    assert_eq!(manager.set_class_long(window, 8, 1, 2), Err(LongPtrError::InvalidIndex));
    // Positive control: the last admitted slot works.
    assert_eq!(manager.set_class_long(window, 6, 0xabcd, 2), Ok(0));
}

#[test]
fn the_menu_name_long_answers_the_pointer_of_the_callers_own_width() {
    let (mut manager, window, _) = manager();
    let record = crate::win32_window::ClassMenuName { ansi: 0x66, wide: 0x67, unicode_string: 0x68 };
    assert_eq!(manager.exchange_class_menu_name(window, record), Ok(crate::win32_window::ClassMenuName::default()));
    assert_eq!(manager.class_long_for(window, GCLP_MENUNAME, 8, false), Ok(0x67));
    assert_eq!(manager.class_long_for(window, GCLP_MENUNAME, 8, true), Ok(0x66));
    // The caller takes back the record the class held, and the class keeps the
    // one the caller handed over.
    let replacement = crate::win32_window::ClassMenuName { ansi: 0x76, wide: 0x77, unicode_string: 0x78 };
    assert_eq!(manager.exchange_class_menu_name(window, replacement), Ok(record));
    assert_eq!(manager.class_long_for(window, GCLP_MENUNAME, 8, false), Ok(0x77));
}

#[test]
fn the_class_description_reports_every_registered_field() {
    let (manager, _, atom) = manager();
    let class = manager.class_description_by_atom(atom).expect("a registered atom must describe its class");
    assert_eq!((class.style, class.cb_wnd_extra, class.cb_cls_extra), (0x0008, 6, 8));
    assert_eq!((class.background, class.cursor, class.icon, class.icon_sm, class.module), (5, 0x1_0001, 7, 9, 0x4000));
}
