//! X pointer input stated in Win32 terms.
//!
//! An X event reports the modifier state that was in effect *before* its own
//! transition, over a bit layout that shares no value with the Win32 mask a
//! pointer message carries. The layer above this one consumes a complete
//! Win32 button state, so the translation and the transition both belong here.

/// Win32 pointer-message mask bits.
pub const MK_LBUTTON: u32 = 0x0001;
pub const MK_RBUTTON: u32 = 0x0002;
pub const MK_SHIFT: u32 = 0x0004;
pub const MK_CONTROL: u32 = 0x0008;
pub const MK_MBUTTON: u32 = 0x0010;
pub const MK_XBUTTON1: u32 = 0x0020;
pub const MK_XBUTTON2: u32 = 0x0040;
/// Every bit a Win32 pointer mask may carry.
pub const MK_ALL: u32 = MK_LBUTTON | MK_RBUTTON | MK_SHIFT | MK_CONTROL | MK_MBUTTON | MK_XBUTTON1 | MK_XBUTTON2;

/// One wheel notch.
pub const WHEEL_DELTA: i32 = 120;

/// X core modifier-state bits.
const STATE_SHIFT: u16 = 1;
const STATE_CONTROL: u16 = 1 << 2;
const STATE_BUTTON1: u16 = 1 << 8;
const STATE_BUTTON2: u16 = 1 << 9;
const STATE_BUTTON3: u16 = 1 << 10;

/// X button numbers.
const BUTTON_LEFT: u8 = 1;
const BUTTON_MIDDLE: u8 = 2;
const BUTTON_RIGHT: u8 = 3;
const BUTTON_WHEEL_UP: u8 = 4;
const BUTTON_WHEEL_DOWN: u8 = 5;
const BUTTON_WHEEL_LEFT: u8 = 6;
const BUTTON_WHEEL_RIGHT: u8 = 7;
const BUTTON_X1: u8 = 8;
const BUTTON_X2: u8 = 9;

/// Held buttons and modifiers a Win32 pointer message carries, from the X
/// state. X reports no state bit for the fourth and fifth buttons, so their
/// mask is carried by the caller across events. # C: O(1)
pub fn buttons_from_state(state: u16) -> u32 {
    let mut buttons = 0;
    if state & STATE_SHIFT != 0 { buttons |= MK_SHIFT; }
    if state & STATE_CONTROL != 0 { buttons |= MK_CONTROL; }
    if state & STATE_BUTTON1 != 0 { buttons |= MK_LBUTTON; }
    if state & STATE_BUTTON2 != 0 { buttons |= MK_MBUTTON; }
    if state & STATE_BUTTON3 != 0 { buttons |= MK_RBUTTON; }
    buttons
}

/// Mask bit one X button holds down while it is pressed. A wheel is a button
/// press in X and holds nothing down in Win32. # C: O(1)
pub fn button_mask(button: u8) -> Option<u32> {
    Some(match button {
        BUTTON_LEFT => MK_LBUTTON, BUTTON_MIDDLE => MK_MBUTTON, BUTTON_RIGHT => MK_RBUTTON,
        BUTTON_X1 => MK_XBUTTON1, BUTTON_X2 => MK_XBUTTON2,
        _ => return None,
    })
}

/// Wheel notches one X button press stands for: the second value says the
/// wheel is horizontal. A wheel button's release stands for nothing.
/// # C: O(1)
pub fn wheel_for(button: u8) -> Option<(i32, bool)> {
    Some(match button {
        BUTTON_WHEEL_UP => (WHEEL_DELTA, false), BUTTON_WHEEL_DOWN => (-WHEEL_DELTA, false),
        BUTTON_WHEEL_LEFT => (-WHEEL_DELTA, true), BUTTON_WHEEL_RIGHT => (WHEEL_DELTA, true),
        _ => return None,
    })
}

#[cfg(test)]
#[path = "tests/pointer.rs"]
mod tests;
