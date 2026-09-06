#[path = "../src/win32_window/settings.rs"]
mod settings;

#[test]
fn caret_blink_user_setting_is_one_canonical_uint_owner() {
    let mut value = settings::UserSettings::new();
    assert_eq!(value.caret_blink_ms(), settings::DEFAULT_CARET_BLINK_MS);
    assert_eq!(value.set_caret_blink_ms(750), 500);
    assert_eq!(value.caret_blink_ms(), 750);
    assert_eq!(value.set_caret_blink_ms(0), 750);
    assert_eq!(value.caret_blink_ms(), 0);
}
