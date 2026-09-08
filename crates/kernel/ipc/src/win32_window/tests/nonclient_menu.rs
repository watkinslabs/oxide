//! Where the menu bar sits in the nonclient area, and the two ways a press or
//! a key reaches menu tracking.
use super::*;

#[test]
fn only_a_top_level_or_popup_window_with_a_menu_carries_a_bar() {
    const WS_CHILD: u32 = 0x4000_0000;
    const WS_POPUP: u32 = 0x8000_0000;
    assert!(window_has_menu_bar(0, 0, Some(7)));
    assert!(window_has_menu_bar(WS_POPUP, 0, Some(7)));
    assert!(!window_has_menu_bar(WS_CHILD, 0, Some(7)));
    assert!(window_has_menu_bar(WS_CHILD | WS_POPUP, 0, Some(7)));
    assert!(!window_has_menu_bar(0, 0, None));
}

#[test]
fn the_bar_band_is_the_gap_the_client_rectangle_leaves_at_the_top() {
    assert_eq!(menu_bar_band(0, 19, true), Some((0, 19)));
    assert_eq!(menu_bar_band(4, 23, true), Some((4, 23)));
    assert_eq!(menu_bar_band(0, 19, false), None);
    assert_eq!(menu_bar_band(0, 0, true), None);
    assert_eq!(menu_bar_band(10, 4, true), None);
}

#[test]
fn a_point_in_the_band_above_the_client_area_hits_the_menu() {
    assert_eq!(menu_bar_hit_test(0, 19, 400, true, 10, 5), Some(HTMENU));
    assert_eq!(menu_bar_hit_test(0, 19, 400, true, 10, 19), None);
    assert_eq!(menu_bar_hit_test(0, 19, 400, true, 400, 5), None);
    assert_eq!(menu_bar_hit_test(0, 19, 400, true, -1, 5), None);
    assert_eq!(menu_bar_hit_test(0, 19, 400, false, 10, 5), None);
}

#[test]
fn a_press_on_the_bar_or_the_window_menu_icon_asks_for_the_matching_command() {
    assert_eq!(nc_button_sys_command(HTMENU), Some(SC_MOUSEMENU));
    assert_eq!(nc_button_sys_command(HTSYSMENU), Some(SC_MOUSEMENU + HTSYSMENU as u32));
    assert_eq!(nc_button_sys_command(HTCLIENT), None);
    assert_eq!(nc_button_sys_command(HTNOWHERE), None);
}

#[test]
fn the_hit_test_a_mouse_menu_command_carries_survives_the_command_decode() {
    assert_eq!(menu_sys_command(SC_MOUSEMENU, 0), Some(MenuCommand::Mouse { hit: 0 }));
    assert_eq!(menu_sys_command(SC_MOUSEMENU + HTSYSMENU as u32, 0), Some(MenuCommand::Mouse { hit: HTSYSMENU }));
    assert_eq!(menu_sys_command(SC_KEYMENU, b'f' as u32), Some(MenuCommand::Keyboard { character: b'f' as u32 }));
    assert_eq!(menu_sys_command(0xf060, 0), None);
}

#[test]
fn a_pressed_and_released_alt_opens_the_bar_with_no_character() {
    let mut latch = KeyMenuLatch::default();
    assert_eq!(latch.key(WM_SYSKEYDOWN, VK_MENU, 0, false, true), None);
    assert_eq!(latch.key(WM_SYSKEYUP, VK_MENU, 0, false, true),
        Some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character: KEYMENU_NO_CHARACTER, target: KeyMenuTarget::Root }));
    assert_eq!(latch.key(WM_SYSKEYUP, VK_MENU, 0, false, true), None);
}

#[test]
fn another_key_pressed_while_alt_is_held_cancels_the_pending_bar() {
    let mut latch = KeyMenuLatch::default();
    assert_eq!(latch.key(WM_SYSKEYDOWN, VK_MENU, 0, false, true), None);
    assert_eq!(latch.key(WM_SYSKEYDOWN, b'F' as u32, 0, false, true), None);
    assert_eq!(latch.key(WM_SYSKEYUP, VK_MENU, 0, false, true), None);
}

#[test]
fn a_pressed_and_released_f10_opens_the_bar_and_shift_f10_asks_for_the_context_menu() {
    let mut latch = KeyMenuLatch::default();
    assert_eq!(latch.key(WM_KEYDOWN, VK_F10, 0, false, false), None);
    assert_eq!(latch.key(WM_KEYUP, VK_F10, 0, false, false),
        Some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character: KEYMENU_NO_CHARACTER, target: KeyMenuTarget::Root }));
    assert_eq!(latch.key(WM_KEYDOWN, VK_F10, 0, true, false), Some(KeyMenuAction::ContextMenu));
}

#[test]
fn shift_escape_opens_the_window_menu_and_alt_space_names_it_by_character() {
    let mut latch = KeyMenuLatch::default();
    assert_eq!(latch.key(WM_KEYDOWN, VK_ESCAPE, 0, true, false),
        Some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character: KEYMENU_SPACE, target: KeyMenuTarget::Window }));
    assert_eq!(latch.key(WM_SYSCHAR, 0, KEYMENU_SPACE, false, true),
        Some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character: KEYMENU_SPACE, target: KeyMenuTarget::Window }));
}

#[test]
fn an_alt_character_names_the_bar_item_while_tab_and_escape_name_none() {
    let mut latch = KeyMenuLatch::default();
    assert_eq!(latch.key(WM_SYSCHAR, 0, b'f' as u32, false, true),
        Some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character: b'f' as u32, target: KeyMenuTarget::Window }));
    assert_eq!(latch.key(WM_SYSCHAR, 0, b'\t' as u32, false, true), None);
    assert_eq!(latch.key(WM_SYSCHAR, 0, VK_ESCAPE, false, true), None);
    assert_eq!(latch.key(WM_SYSCHAR, 0, b'f' as u32, false, false), Some(KeyMenuAction::Beep));
}

/// Alt+F4 is the system key that closes a window; the routing of the command
/// past a class that refuses to close is the caller's.
#[test]
fn alt_f4_is_a_close_and_the_other_alt_keys_are_not() {
    let mut latch = KeyMenuLatch::default();
    assert_eq!(latch.key(WM_SYSKEYDOWN, VK_F4, 0, false, true), Some(KeyMenuAction::Close));
    assert_eq!(latch.key(WM_SYSKEYDOWN, VK_F4, 0, false, false), None);
    assert_eq!(latch.key(WM_SYSKEYDOWN, b'F' as u32, 0, false, true), None);
    // The close does not leave a bare-Alt opening armed behind it.
    assert_eq!(latch.key(WM_SYSKEYUP, VK_MENU, 0, false, true), None);
}

/// A bare Alt is answered by the root of the window tree it was typed into,
/// which is what lets a focused child open its top-level window's menu bar.
#[test]
fn a_bare_alt_opens_the_root_window_and_a_character_stays_on_the_window() {
    let mut latch = KeyMenuLatch::default();
    assert_eq!(latch.key(WM_SYSKEYDOWN, VK_MENU, 0, false, true), None);
    assert_eq!(latch.key(WM_SYSKEYUP, VK_MENU, 0, false, true),
        Some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character: KEYMENU_NO_CHARACTER, target: KeyMenuTarget::Root }));
    assert_eq!(latch.key(WM_SYSCHAR, 0, b'f' as u32, false, true),
        Some(KeyMenuAction::SysCommand { command: SC_KEYMENU, character: b'f' as u32, target: KeyMenuTarget::Window }));
}
