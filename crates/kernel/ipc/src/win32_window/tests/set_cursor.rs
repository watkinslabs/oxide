use super::*;

fn target(hit: i16, message: u32) -> SetCursorTarget { set_cursor_action(hit, message).target }

#[test]
fn the_client_area_asks_for_the_class_cursor() {
    assert_eq!(target(HTCLIENT, 0x0200), SetCursorTarget::ClassCursor);
}

#[test]
fn each_resize_border_names_its_own_oem_cursor() {
    assert_eq!(target(HTLEFT, 0), SetCursorTarget::OemCursor(IDC_SIZEWE));
    assert_eq!(target(HTRIGHT, 0), SetCursorTarget::OemCursor(IDC_SIZEWE));
    assert_eq!(target(HTTOP, 0), SetCursorTarget::OemCursor(IDC_SIZENS));
    assert_eq!(target(HTBOTTOM, 0), SetCursorTarget::OemCursor(IDC_SIZENS));
    assert_eq!(target(HTTOPLEFT, 0), SetCursorTarget::OemCursor(IDC_SIZENWSE));
    assert_eq!(target(HTBOTTOMRIGHT, 0), SetCursorTarget::OemCursor(IDC_SIZENWSE));
    assert_eq!(target(HTTOPRIGHT, 0), SetCursorTarget::OemCursor(IDC_SIZENESW));
    assert_eq!(target(HTBOTTOMLEFT, 0), SetCursorTarget::OemCursor(IDC_SIZENESW));
}

#[test]
fn every_other_hit_test_code_falls_back_to_the_arrow() {
    for hit in [0i16, 2, 3, 5, 18, 20] { assert_eq!(target(hit, 0), SetCursorTarget::OemCursor(IDC_ARROW)); }
}

#[test]
fn an_error_area_beeps_only_for_a_button_press_and_still_installs_the_arrow() {
    for message in [0x0201u32, 0x0204, 0x0207, 0x020b] {
        assert_eq!(set_cursor_action(HTERROR, message), SetCursorAction { beep: true, target: SetCursorTarget::OemCursor(IDC_ARROW) });
    }
    assert_eq!(set_cursor_action(HTERROR, 0x0200), SetCursorAction { beep: false, target: SetCursorTarget::OemCursor(IDC_ARROW) });
    assert!(!set_cursor_action(HTCLIENT, 0x0201).beep);
}

#[test]
fn a_child_yields_to_its_parent_everywhere_but_the_resize_border() {
    assert!(parent_gets_first_chance(true, false, HTCLIENT));
    assert!(!parent_gets_first_chance(true, false, HTLEFT));
    assert!(!parent_gets_first_chance(true, false, HTBOTTOMRIGHT));
    assert!(parent_gets_first_chance(true, false, 18));
    assert!(!parent_gets_first_chance(true, true, HTCLIENT));
    assert!(!parent_gets_first_chance(false, false, HTCLIENT));
}

#[test]
fn the_lparam_carries_the_hit_test_code_below_the_originating_message() {
    assert_eq!(split_lparam(0x0200_0001), (HTCLIENT, 0x0200));
    assert_eq!(split_lparam(0x0201_fffe), (HTERROR, 0x0201));
}
