//! Window tree, state and attribute ordinals. Every decision lives in the
//! window owner; this module names the ordinals and decodes their records.

pub(crate) const ALTER_WINDOW_STYLE: u64 = 0x131e;
pub(crate) const ARRANGE_ICONIC_WINDOWS: u64 = 0x1320;
pub(crate) const BEGIN_DEFER_WINDOW_POS: u64 = 0x1325;
pub(crate) const BUILD_HWND_LIST: u64 = 0x132d;
pub(crate) const BUILD_PROP_LIST: u64 = 0x132f;
pub(crate) const CHILD_WINDOW_FROM_POINT_EX: u64 = 0x134b;
pub(crate) const DEFER_WINDOW_POS_AND_BAND: u64 = 0x1374;
pub(crate) const ENABLE_WINDOW: u64 = 0x13b5;
pub(crate) const END_DEFER_WINDOW_POS_EX: u64 = 0x13ba;
pub(crate) const FIND_WINDOW_EX: u64 = 0x13c6;
pub(crate) const FLASH_WINDOW_EX: u64 = 0x13c7;
pub(crate) const GET_ANCESTOR: u64 = 0x13ce;
pub(crate) const GET_FOREGROUND_WINDOW: u64 = 0x13fa;
pub(crate) const GET_GUI_THREAD_INFO: u64 = 0x13fb;
pub(crate) const GET_INTERNAL_WINDOW_POS: u64 = 0x140e;
pub(crate) const GET_LAYERED_ATTRIBUTES: u64 = 0x1416;
pub(crate) const GET_TITLE_BAR_INFO: u64 = 0x144f;
pub(crate) const GET_WINDOW_CONTEXT_HELP_ID: u64 = 0x145d;
pub(crate) const GET_WINDOW_DC: u64 = 0x145e;
pub(crate) const GET_WINDOW_DISPLAY_AFFINITY: u64 = 0x145f;
pub(crate) const GET_WINDOW_RGN_EX: u64 = 0x1465;
pub(crate) const INTERNAL_GET_WINDOW_TEXT: u64 = 0x1489;
pub(crate) const LOCK_WINDOW_UPDATE: u64 = 0x14a5;
pub(crate) const PRINT_WINDOW: u64 = 0x14d4;
pub(crate) const REAL_CHILD_WINDOW_FROM_POINT: u64 = 0x14e1;
pub(crate) const SET_FOREGROUND_WINDOW: u64 = 0x1559;
pub(crate) const SET_INTERNAL_WINDOW_POS: u64 = 0x1564;
pub(crate) const SET_LAYERED_ATTRIBUTES: u64 = 0x1566;
pub(crate) const SET_PARENT: u64 = 0x1574;
pub(crate) const SET_PROGMAN_WINDOW: u64 = 0x157e;
pub(crate) const SET_SHELL_WINDOW_EX: u64 = 0x1585;
pub(crate) const SET_TASKMAN_WINDOW: u64 = 0x158e;
pub(crate) const SET_WINDOW_CONTEXT_HELP_ID: u64 = 0x159e;
pub(crate) const SET_WINDOW_RGN: u64 = 0x15a8;
pub(crate) const SHOW_OWNED_POPUPS: u64 = 0x15b9;
pub(crate) const SHOW_WINDOW_ASYNC: u64 = 0x15be;
pub(crate) const UPDATE_LAYERED_WINDOW: u64 = 0x15e7;
pub(crate) const WINDOW_FROM_DC: u64 = 0x15fd;
pub(crate) const WINDOW_FROM_POINT: u64 = 0x15ff;

/// `FLASHWINFO`: its own size, the window, the flags, the blink count and the
/// blink period.
pub(crate) const FLASHWINFO_SIZE: u64 = 0;
pub(crate) const FLASHWINFO_HWND: u64 = 8;
pub(crate) const FLASHWINFO_FLAGS: u64 = 16;
pub(crate) const FLASHWINFO_BYTES: u32 = 32;
/// Flash the caption; absent flags stop the flashing instead.
pub(crate) const FLASHW_CAPTION: u32 = 0x0000_0001;

/// `GUITHREADINFO`: its own size, the flags, then the six windows and the
/// caret rectangle.
pub(crate) const GUITHREADINFO_SIZE: u64 = 0;
pub(crate) const GUITHREADINFO_FLAGS: u64 = 4;
pub(crate) const GUITHREADINFO_ACTIVE: u64 = 8;
pub(crate) const GUITHREADINFO_FOCUS: u64 = 16;
pub(crate) const GUITHREADINFO_CAPTURE: u64 = 24;
pub(crate) const GUITHREADINFO_MENU_OWNER: u64 = 32;
pub(crate) const GUITHREADINFO_MOVE_SIZE: u64 = 40;
pub(crate) const GUITHREADINFO_CARET: u64 = 48;
pub(crate) const GUITHREADINFO_CARET_RECT: u64 = 56;
pub(crate) const GUITHREADINFO_BYTES: u32 = 72;

/// `TITLEBARINFO`: its own size, the bar rectangle, then the element states.
pub(crate) const TITLEBARINFO_SIZE: u64 = 0;
pub(crate) const TITLEBARINFO_RECT: u64 = 4;
pub(crate) const TITLEBARINFO_STATE: u64 = 20;
pub(crate) const TITLEBARINFO_BYTES: u32 = 44;

/// `struct ntuser_property_list` entry: the value, the atom and whether the
/// atom came from a string.
pub(crate) const PROPERTY_ENTRY_BYTES: u64 = 16;
pub(crate) const PROPERTY_ENTRY_DATA: u64 = 0;
pub(crate) const PROPERTY_ENTRY_ATOM: u64 = 8;
pub(crate) const PROPERTY_ENTRY_STRING: u64 = 12;

/// The thread-information flag that marks a blinking caret. The move-size and
/// menu-mode flags belong to states this owner does not enter.
pub(crate) const GUI_CARETBLINKING: u32 = 0x0000_0001;

/// Whether one ordinal belongs to this family. # C: O(1)
pub(crate) const fn claims(ordinal: u64) -> bool {
    matches!(ordinal, ALTER_WINDOW_STYLE | ARRANGE_ICONIC_WINDOWS | BEGIN_DEFER_WINDOW_POS
        | BUILD_HWND_LIST | BUILD_PROP_LIST | CHILD_WINDOW_FROM_POINT_EX | DEFER_WINDOW_POS_AND_BAND
        | ENABLE_WINDOW | END_DEFER_WINDOW_POS_EX | FIND_WINDOW_EX | FLASH_WINDOW_EX | GET_ANCESTOR
        | GET_FOREGROUND_WINDOW | GET_GUI_THREAD_INFO | GET_INTERNAL_WINDOW_POS | GET_LAYERED_ATTRIBUTES
        | GET_TITLE_BAR_INFO | GET_WINDOW_CONTEXT_HELP_ID | GET_WINDOW_DC | GET_WINDOW_DISPLAY_AFFINITY
        | GET_WINDOW_RGN_EX | INTERNAL_GET_WINDOW_TEXT | LOCK_WINDOW_UPDATE | PRINT_WINDOW
        | REAL_CHILD_WINDOW_FROM_POINT | SET_FOREGROUND_WINDOW | SET_INTERNAL_WINDOW_POS
        | SET_LAYERED_ATTRIBUTES | SET_PARENT | SET_PROGMAN_WINDOW | SET_SHELL_WINDOW_EX
        | SET_TASKMAN_WINDOW | SET_WINDOW_CONTEXT_HELP_ID | SET_WINDOW_RGN | SHOW_OWNED_POPUPS
        | SHOW_WINDOW_ASYNC | UPDATE_LAYERED_WINDOW | WINDOW_FROM_DC | WINDOW_FROM_POINT)
}

/// Whether a caller's record announces the size this build knows. A record of
/// any other size is a parameter error, which is how these calls guard against
/// a caller compiled for a different layout. # C: O(1)
pub(crate) const fn record_size_matches(declared: u32, expected: u32) -> bool { declared == expected }

/// The filters `RealChildWindowFromPoint` applies. # C: O(1)
pub(crate) const fn real_child_flags() -> u32 {
    ipc::win32_window::CWP_SKIPTRANSPARENT | ipc::win32_window::CWP_SKIPINVISIBLE
}

/// Whether flashing should mark the non-client area active. A call with no
/// flags stops the flashing instead. # C: O(1)
pub(crate) const fn flash_activates(flags: u32, already_active: bool) -> Option<bool> {
    if flags == 0 { return Some(false); }
    if flags & FLASHW_CAPTION != 0 && !already_active { return Some(true); }
    None
}

#[cfg(target_os = "oxide-kernel")]
#[path = "window_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/window_raw.rs"]
mod tests;
