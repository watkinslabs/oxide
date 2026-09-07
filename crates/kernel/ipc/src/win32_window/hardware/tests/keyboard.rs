use super::keyboard::*;
use super::ladder::ProcCall;
use super::uapi::*;
use super::super::{WinMessage, WindowId};

const WINDOW: u32 = 0x41;

fn ctx() -> KeyContext { KeyContext { remove: true, desktop: false, menu_active: false, first: 0, last: u32::MAX } }

fn key(message: u32, vkey: u64) -> WinMessage {
    WinMessage { hwnd: WindowId::from_raw(WINDOW), message, wparam: vkey, lparam: 1 }
}

#[test]
fn the_side_specific_modifiers_reach_the_application_as_the_generic_key() {
    for (side, generic) in [(VK_LSHIFT, VK_SHIFT), (VK_RSHIFT, VK_SHIFT), (VK_LCONTROL, VK_CONTROL),
        (VK_RCONTROL, VK_CONTROL), (VK_LMENU, VK_MENU), (VK_RMENU, VK_MENU)] {
        for message in [WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP] {
            assert_eq!(prepare(key(message, side), &ctx()).message.wparam, generic);
        }
    }
    assert_eq!(prepare(key(WM_KEYDOWN, VK_F1), &ctx()).message.wparam, VK_F1);
}

#[test]
fn a_filtered_key_is_dropped_and_makes_no_extra_message() {
    let context = KeyContext { first: WM_MOUSEMOVE, last: WM_MOUSELAST, ..ctx() };
    let prepared = prepare(key(WM_KEYDOWN, VK_F1), &context);
    assert_eq!(prepared.outcome, KeyOutcome::Filtered);
    assert_eq!(prepared.extra, None);
}

#[test]
fn the_help_key_posts_its_own_message_except_on_the_desktop() {
    let prepared = prepare(key(WM_KEYDOWN, VK_F1), &ctx());
    assert_eq!(prepared.outcome, KeyOutcome::Deliver);
    assert_eq!(prepared.extra, Some(KeyExtra { call: ProcCall { hwnd: WINDOW, message: WM_KEYF1, wparam: 0, lparam: 0 }, post: true }));
    assert_eq!(prepare(key(WM_KEYDOWN, VK_F1), &KeyContext { desktop: true, ..ctx() }).extra, None);
    // Releasing the key makes nothing.
    assert_eq!(prepare(key(WM_KEYUP, VK_F1), &ctx()).extra, None);
}

#[test]
fn the_application_command_keys_are_sent_as_a_keyboard_sourced_command() {
    for (vkey, command) in [(VK_BROWSER_BACK, 1), (VK_LAUNCH_APP2, VK_LAUNCH_APP2 - VK_BROWSER_BACK + 1)] {
        let extra = prepare(key(WM_KEYDOWN, vkey), &ctx()).extra.expect("no command");
        assert!(!extra.post);
        assert_eq!(extra.call, ProcCall { hwnd: WINDOW, message: WM_APPCOMMAND, wparam: WINDOW as u64,
            lparam: make_point(0, (FAPPCOMMAND_KEY | command as u32) as i32) });
    }
    // Either side of the range makes nothing.
    assert_eq!(prepare(key(WM_KEYDOWN, VK_BROWSER_BACK - 1), &ctx()).extra, None);
    assert_eq!(prepare(key(WM_KEYDOWN, VK_LAUNCH_APP2 + 1), &ctx()).extra, None);
}

#[test]
fn the_applications_key_posts_a_context_menu_unless_a_menu_owns_it() {
    let extra = prepare(key(WM_KEYUP, VK_APPS), &ctx()).extra.expect("no context menu");
    assert!(extra.post);
    assert_eq!(extra.call, ProcCall { hwnd: WINDOW, message: WM_CONTEXTMENU, wparam: WINDOW as u64, lparam: -1 });
    assert_eq!(prepare(key(WM_KEYUP, VK_APPS), &KeyContext { menu_active: true, ..ctx() }).extra, None);
    assert_eq!(prepare(key(WM_KEYDOWN, VK_APPS), &ctx()).extra, None);
}

#[test]
fn a_peek_makes_no_extra_message_at_all() {
    let context = KeyContext { remove: false, ..ctx() };
    for (message, vkey) in [(WM_KEYDOWN, VK_F1), (WM_KEYDOWN, VK_BROWSER_BACK), (WM_KEYUP, VK_APPS)] {
        let prepared = prepare(key(message, vkey), &context);
        assert_eq!(prepared.outcome, KeyOutcome::Deliver);
        assert_eq!(prepared.extra, None);
    }
}
