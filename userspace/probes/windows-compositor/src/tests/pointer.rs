use super::*;

#[test]
fn x_state_bits_are_not_win32_mask_bits() {
    // The X shift bit shares its value with the Win32 left-button bit, and the
    // X button bits sit above the whole Win32 mask; passing one through as the
    // other reports a click that never happened and loses the one that did.
    assert_eq!(buttons_from_state(STATE_SHIFT), MK_SHIFT);
    assert_eq!(buttons_from_state(STATE_CONTROL), MK_CONTROL);
    assert_eq!(buttons_from_state(STATE_BUTTON1), MK_LBUTTON);
    assert_eq!(buttons_from_state(STATE_BUTTON2), MK_MBUTTON);
    assert_eq!(buttons_from_state(STATE_BUTTON3), MK_RBUTTON);
    assert_eq!(buttons_from_state(STATE_BUTTON1 | STATE_CONTROL), MK_LBUTTON | MK_CONTROL);
    // The lock and modifier bits X reports carry no Win32 pointer meaning.
    assert_eq!(buttons_from_state(1 << 1 | 1 << 3 | 1 << 7), 0);
}

#[test]
fn wheel_buttons_hold_nothing_and_named_buttons_do_not_wheel() {
    assert_eq!(button_mask(1), Some(MK_LBUTTON));
    assert_eq!(button_mask(2), Some(MK_MBUTTON));
    assert_eq!(button_mask(3), Some(MK_RBUTTON));
    assert_eq!(button_mask(8), Some(MK_XBUTTON1));
    assert_eq!(button_mask(9), Some(MK_XBUTTON2));
    for button in [4u8, 5, 6, 7, 0, 10] { assert_eq!(button_mask(button), None); }
    assert_eq!(wheel_for(4), Some((WHEEL_DELTA, false)));
    assert_eq!(wheel_for(5), Some((-WHEEL_DELTA, false)));
    assert_eq!(wheel_for(6), Some((-WHEEL_DELTA, true)));
    assert_eq!(wheel_for(7), Some((WHEEL_DELTA, true)));
    for button in [1u8, 2, 3, 8, 9, 0, 10] { assert_eq!(wheel_for(button), None); }
}
