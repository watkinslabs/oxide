//! Effective-child classification of a creation `hMenu` word.
use super::*;
use ipc::win32_window::styles::{WS_CHILD, WS_POPUP};

#[test]
fn popup_wins_over_child_and_a_child_menu_word_is_a_control_id() {
    assert!(is_effective_child(WS_CHILD));
    assert!(!is_effective_child(WS_CHILD | WS_POPUP));
    assert!(!is_effective_child(0));
    assert_eq!(classify_create_menu(WS_CHILD, u64::MAX), CreateMenuValue::ChildControlId(u64::MAX));
    assert_eq!(classify_create_menu(WS_CHILD | WS_POPUP, u64::MAX), CreateMenuValue::MenuHandle(u64::MAX));
    assert_eq!(classify_create_menu(0, u64::MAX), CreateMenuValue::MenuHandle(u64::MAX));
    // A zero word is neither, whatever the style.
    assert_eq!(classify_create_menu(WS_CHILD, 0), CreateMenuValue::None);
    assert_eq!(classify_create_menu(0, 0), CreateMenuValue::None);
}
