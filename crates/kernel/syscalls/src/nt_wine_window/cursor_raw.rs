//! Cursor ABI: the two cursor ordinals and the default WM_SETCURSOR handler.
use ipc::win32_window::{SetCursorTarget, set_cursor_action, split_lparam};

pub(crate) const GET_CURSOR: u64 = 0x13e7;
pub(crate) const SET_CURSOR: u64 = 0x1546;

/// What the default WM_SETCURSOR handler must ask the owner for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetCursorStep {
    /// Install the class cursor of the named window; answer TRUE, or FALSE
    /// when that class carries none.
    ClassCursor { hwnd: u64, beep: bool },
    /// Load the shared OEM cursor and install it; answer the cursor it replaced.
    OemCursor { id: u32, beep: bool },
}

/// Decode one WM_SETCURSOR into the single step it performs. wParam names the
/// window whose class cursor applies, not the window handling the message.
/// # C: O(1)
pub(crate) fn set_cursor_step(wparam: u64, lparam: u64) -> SetCursorStep {
    let (hit_test, message) = split_lparam(lparam);
    let action = set_cursor_action(hit_test, message);
    match action.target {
        SetCursorTarget::ClassCursor => SetCursorStep::ClassCursor { hwnd: wparam, beep: action.beep },
        SetCursorTarget::OemCursor(id) => SetCursorStep::OemCursor { id, beep: action.beep },
    }
}

/// Run one decoded step. `class_cursor` and `load` answer zero when the owner
/// has nothing; installing answers the previous cursor. # C: O(owner work)
pub(crate) fn apply_set_cursor(step: SetCursorStep, class_cursor: impl FnOnce(u64) -> u64,
    load: impl FnOnce(u32) -> u64, install: impl FnOnce(u64) -> u64) -> u64 {
    match step {
        SetCursorStep::ClassCursor { hwnd, .. } => {
            let cursor = class_cursor(hwnd);
            if cursor == 0 { return 0; }
            install(cursor);
            1
        }
        SetCursorStep::OemCursor { id, .. } => {
            let cursor = load(id);
            install(cursor)
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
#[path = "cursor_raw/kernel.rs"]
mod kernel;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use kernel::{default_set_cursor, route};

#[cfg(test)]
#[path = "tests/cursor_raw.rs"]
mod tests;
