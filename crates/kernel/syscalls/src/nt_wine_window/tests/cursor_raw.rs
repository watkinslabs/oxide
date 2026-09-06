use super::*;

const HWND: u64 = 0x44;
const IDC_ARROW: u32 = 32512;
const IDC_SIZEWE: u32 = 32644;

#[test]
fn the_client_area_step_names_the_window_from_wparam() {
    assert_eq!(set_cursor_step(HWND, 0x0200_0001), SetCursorStep::ClassCursor { hwnd: HWND, beep: false });
}

#[test]
fn a_resize_border_step_names_its_oem_cursor_and_an_error_area_beeps() {
    assert_eq!(set_cursor_step(HWND, 0x0000_000a), SetCursorStep::OemCursor { id: IDC_SIZEWE, beep: false });
    assert_eq!(set_cursor_step(HWND, 0x0201_fffe), SetCursorStep::OemCursor { id: IDC_ARROW, beep: true });
}

#[test]
fn a_class_with_no_cursor_answers_false_and_never_touches_the_pointer() {
    let mut installed = alloc::vec::Vec::new();
    let result = apply_set_cursor(SetCursorStep::ClassCursor { hwnd: HWND, beep: false }, |_| 0,
        |_| panic!("the client area never loads an OEM cursor"), |cursor| { installed.push(cursor); 0 });
    assert_eq!(result, 0);
    assert!(installed.is_empty());
}

#[test]
fn a_class_cursor_is_installed_and_answers_true() {
    let mut installed = alloc::vec::Vec::new();
    let result = apply_set_cursor(SetCursorStep::ClassCursor { hwnd: HWND, beep: false }, |hwnd| { assert_eq!(hwnd, HWND); 0x1_0001 },
        |_| 0, |cursor| { installed.push(cursor); 0x1_0009 });
    assert_eq!(result, 1);
    assert_eq!(installed, alloc::vec![0x1_0001]);
}

#[test]
fn an_oem_step_answers_the_cursor_it_replaced() {
    let result = apply_set_cursor(SetCursorStep::OemCursor { id: IDC_SIZEWE, beep: false },
        |_| panic!("a border never reads the class cursor"), |id| { assert_eq!(id, IDC_SIZEWE); 0x1_0002 }, |cursor| { assert_eq!(cursor, 0x1_0002); 0x1_0007 });
    assert_eq!(result, 0x1_0007);
}
