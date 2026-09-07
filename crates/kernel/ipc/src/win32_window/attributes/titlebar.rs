//! Title-bar element state derived from a window's styles.
use super::*;

pub const STATE_SYSTEM_UNAVAILABLE: u32 = 0x0000_0001;
pub const STATE_SYSTEM_INVISIBLE: u32 = 0x0000_8000;
pub const STATE_SYSTEM_FOCUSABLE: u32 = 0x0010_0000;

/// Title bar, then its five buttons: minimize, maximize, help and close.
pub const TITLE_BAR_ELEMENTS: usize = 6;

/// State of every title-bar element. Element zero is the bar itself, which is
/// always focusable; the buttons exist only under a caption with a system
/// menu, are unavailable when their style bit is absent, and the close button
/// is unavailable when the class forbids closing. # C: O(1)
pub fn title_bar_state(style: u32, ex_style: u32, class_style: u32) -> [u32; TITLE_BAR_ELEMENTS] {
    let mut state = [0u32; TITLE_BAR_ELEMENTS];
    state[0] = STATE_SYSTEM_FOCUSABLE;
    if style & WS_CAPTION == 0 { return state; }
    state[1] = STATE_SYSTEM_INVISIBLE;
    if style & WS_SYSMENU == 0 { return state; }
    if style & (WS_MINIMIZEBOX | WS_MAXIMIZEBOX) == 0 {
        state[2] = STATE_SYSTEM_INVISIBLE;
        state[3] = STATE_SYSTEM_INVISIBLE;
    } else {
        if style & WS_MINIMIZEBOX == 0 { state[2] = STATE_SYSTEM_UNAVAILABLE; }
        if style & WS_MAXIMIZEBOX == 0 { state[3] = STATE_SYSTEM_UNAVAILABLE; }
    }
    if ex_style & WS_EX_CONTEXTHELP == 0 { state[4] = STATE_SYSTEM_INVISIBLE; }
    if class_style & CS_NOCLOSE != 0 { state[5] = STATE_SYSTEM_UNAVAILABLE; }
    state
}
