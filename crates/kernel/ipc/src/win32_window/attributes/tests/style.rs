//! Style-bit edits, the AlterWindowStyle mask and the enable transition.
use super::*;

fn one() -> (WindowManager, WindowId) {
    let mut windows = WindowManager::new();
    let id = windows.create(1, None, 0).unwrap();
    (windows, id)
}

#[test]
fn a_style_edit_answers_the_previous_style_and_keeps_visibility_in_step() {
    let (mut windows, id) = one();
    assert_eq!(windows.set_style_bits(id, WS_VISIBLE | WS_CAPTION, 0), Ok(0));
    assert!(windows.get(id).unwrap().visible);
    assert_eq!(windows.set_style_bits(id, 0, WS_VISIBLE), Ok(WS_VISIBLE | WS_CAPTION));
    assert!(!windows.get(id).unwrap().visible);
    assert_eq!(windows.get(id).unwrap().style, WS_CAPTION);
}

#[test]
fn a_style_edit_on_an_unknown_window_is_reported() {
    let (mut windows, id) = one();
    windows.destroy(id).unwrap();
    assert_eq!(windows.set_style_bits(id, WS_VISIBLE, 0), Err(WindowError::NoSuchWindow));
    assert_eq!(windows.set_ex_style_bits(id, WS_EX_LAYERED, 0), Err(WindowError::NoSuchWindow));
}

#[test]
fn alter_style_reaches_only_the_bits_the_call_owns() {
    let (mut windows, id) = one();
    windows.set_style_bits(id, WS_CAPTION | WS_VSCROLL, 0).unwrap();
    // WS_CAPTION is outside the alterable mask, so asking to clear it does nothing.
    windows.alter_style(id, WS_CAPTION | WS_VSCROLL, 0).unwrap();
    assert_eq!(windows.get(id).unwrap().style, WS_CAPTION);
    windows.alter_style(id, WS_HSCROLL, WS_HSCROLL).unwrap();
    assert_eq!(windows.get(id).unwrap().style, WS_CAPTION | WS_HSCROLL);
    // The low alterable bits are reachable; anything above them is not.
    windows.alter_style(id, 0xffff_ffff, 0x0000_0201 | WS_MINIMIZE).unwrap();
    assert_eq!(windows.get(id).unwrap().style & WS_MINIMIZE, 0);
    assert_eq!(windows.get(id).unwrap().style & 0x0000_0201, 0x0000_0201);
}

#[test]
fn disabling_a_window_reports_that_it_was_enabled_and_enabling_it_again_reports_the_change() {
    let (mut windows, id) = one();
    assert!(windows.is_enabled(id));
    let disabled = windows.enable_window(id, false).unwrap();
    assert_eq!((disabled.previously_disabled, disabled.changed), (false, true));
    assert!(!windows.is_enabled(id));
    let again = windows.enable_window(id, false).unwrap();
    assert_eq!((again.previously_disabled, again.changed), (true, false));
    let enabled = windows.enable_window(id, true).unwrap();
    assert_eq!((enabled.previously_disabled, enabled.changed), (true, true));
    assert!(windows.is_enabled(id));
}

#[test]
fn a_disabled_window_gives_up_the_focus() {
    let (mut windows, id) = one();
    windows.show(1, id, true).unwrap();
    windows.set_focus(1, Some(id)).unwrap();
    assert_eq!(windows.focused(), Some(id));
    let outcome = windows.enable_window(id, false).unwrap();
    assert!(outcome.clear_focus);
    assert_eq!(windows.focused(), None);
    // Re-enabling does not hand the focus back.
    assert!(!windows.enable_window(id, true).unwrap().clear_focus);
    assert_eq!(windows.focused(), None);
}

#[test]
fn the_title_bar_is_focusable_even_without_a_caption() {
    let state = title_bar_state(0, 0, 0);
    assert_eq!(state[0], STATE_SYSTEM_FOCUSABLE);
    assert_eq!(state[1..], [0; TITLE_BAR_ELEMENTS - 1]);
}

#[test]
fn a_caption_without_a_system_menu_leaves_the_buttons_alone() {
    let state = title_bar_state(WS_CAPTION, 0, 0);
    assert_eq!(state[1], STATE_SYSTEM_INVISIBLE);
    assert_eq!(state[2..], [0; TITLE_BAR_ELEMENTS - 2]);
}

#[test]
fn a_system_menu_without_either_size_box_hides_both_size_buttons() {
    let state = title_bar_state(WS_CAPTION | WS_SYSMENU, 0, 0);
    assert_eq!((state[2], state[3]), (STATE_SYSTEM_INVISIBLE, STATE_SYSTEM_INVISIBLE));
    assert_eq!(state[4], STATE_SYSTEM_INVISIBLE);
}

#[test]
fn a_single_size_box_leaves_the_other_button_present_but_unavailable() {
    let state = title_bar_state(WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 0, 0);
    assert_eq!((state[2], state[3]), (0, STATE_SYSTEM_UNAVAILABLE));
    let state = title_bar_state(WS_CAPTION | WS_SYSMENU | WS_MAXIMIZEBOX, 0, 0);
    assert_eq!((state[2], state[3]), (STATE_SYSTEM_UNAVAILABLE, 0));
}

#[test]
fn the_help_button_appears_only_with_its_extended_style_and_close_follows_the_class() {
    let state = title_bar_state(WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, WS_EX_CONTEXTHELP, 0);
    assert_eq!((state[4], state[5]), (0, 0));
    let state = title_bar_state(WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, WS_EX_CONTEXTHELP, CS_NOCLOSE);
    assert_eq!(state[5], STATE_SYSTEM_UNAVAILABLE);
}
