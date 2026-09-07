use super::*;
use crate::win32_window::WindowManager;

const TID: u64 = 6;

#[test]
fn the_locale_layout_carries_the_locale_in_both_halves() {
    assert_eq!(locale_layout(DEFAULT_LOCALE), 0x0409_0409);
    assert_eq!(layout_name(0x0409_0409), alloc::vec![0x30, 0x30, 0x30, 0x30, 0x30, 0x34, 0x30, 0x39]);
    assert_eq!(layout_name(0xf001_0409).len(), KL_NAMELENGTH - 1);
}

#[test]
fn a_thread_starts_on_the_locale_layout() {
    let manager = WindowManager::new();
    assert_eq!(manager.keyboard_layout(TID), locale_layout(DEFAULT_LOCALE));
    assert_eq!(manager.keyboard_layout_list(), alloc::vec![locale_layout(DEFAULT_LOCALE)]);
}

#[test]
fn a_relative_activation_and_a_foreign_locale_are_both_refused() {
    assert_eq!(activate_layout(0, DEFAULT_LOCALE), Err(LayoutError::NotImplemented));
    assert_eq!(activate_layout(1, DEFAULT_LOCALE), Err(LayoutError::NotImplemented));
    assert_eq!(activate_layout(0x0407_0407, DEFAULT_LOCALE), Err(LayoutError::NotImplemented));
}

#[test]
fn the_user_locale_and_the_invariant_language_are_both_admitted() {
    assert_eq!(activate_layout(0x0409_0409, DEFAULT_LOCALE), Ok(0x0409_0409));
    assert_eq!(activate_layout(0x0000_047f, DEFAULT_LOCALE), Ok(0x0000_047f));
}

#[test]
fn activating_answers_the_previous_layout_and_records_the_new_one() {
    let mut manager = WindowManager::new();
    assert_eq!(manager.activate_keyboard_layout(TID, 0x0000_047f), Ok(locale_layout(DEFAULT_LOCALE)));
    assert_eq!(manager.keyboard_layout(TID), 0x0000_047f);
    assert_eq!(manager.activate_keyboard_layout(TID, 0x0409_0409), Ok(0x0000_047f));
    assert_eq!(manager.keyboard_layout_list().len(), 1);
}
