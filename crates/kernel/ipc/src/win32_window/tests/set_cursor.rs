use super::*;

#[test]
fn the_client_area_asks_for_the_class_cursor() {
    assert_eq!(set_cursor_action(HTCLIENT, 0x0200), SetCursorAction::ClassCursor);
}

#[test]
fn each_resize_border_names_its_own_oem_cursor() {
    assert_eq!(set_cursor_action(HTLEFT, 0), SetCursorAction::OemCursor(IDC_SIZEWE));
    assert_eq!(set_cursor_action(HTRIGHT, 0), SetCursorAction::OemCursor(IDC_SIZEWE));
    assert_eq!(set_cursor_action(HTTOP, 0), SetCursorAction::OemCursor(IDC_SIZENS));
    assert_eq!(set_cursor_action(HTBOTTOM, 0), SetCursorAction::OemCursor(IDC_SIZENS));
    assert_eq!(set_cursor_action(HTTOPLEFT, 0), SetCursorAction::OemCursor(IDC_SIZENWSE));
    assert_eq!(set_cursor_action(HTBOTTOMRIGHT, 0), SetCursorAction::OemCursor(IDC_SIZENWSE));
    assert_eq!(set_cursor_action(HTTOPRIGHT, 0), SetCursorAction::OemCursor(IDC_SIZENESW));
    assert_eq!(set_cursor_action(HTBOTTOMLEFT, 0), SetCursorAction::OemCursor(IDC_SIZENESW));
}

#[test]
fn every_other_hit_test_code_falls_back_to_the_arrow() {
    for hit in [0i16, 2, 3, 5, 18, 20] { assert_eq!(set_cursor_action(hit, 0), SetCursorAction::OemCursor(IDC_ARROW)); }
}

#[test]
fn an_error_area_beeps_only_for_a_button_press() {
    assert_eq!(set_cursor_action(HTERROR, 0x0201), SetCursorAction::Beep);
    assert_eq!(set_cursor_action(HTERROR, 0x0204), SetCursorAction::Beep);
    assert_eq!(set_cursor_action(HTERROR, 0x0207), SetCursorAction::Beep);
    assert_eq!(set_cursor_action(HTERROR, 0x020b), SetCursorAction::Beep);
    assert_eq!(set_cursor_action(HTERROR, 0x0200), SetCursorAction::None);
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
