//! Default WM_SETCURSOR handling: which cursor a hit-test code asks for, and
//! whether the parent gets first refusal.
use super::cursor::{IDC_ARROW, IDC_SIZENESW, IDC_SIZENS, IDC_SIZENWSE, IDC_SIZEWE};

pub const WM_SETCURSOR: u32 = 0x0020;
pub const HTERROR: i16 = -2;
pub const HTCLIENT: i16 = 1;
pub const HTLEFT: i16 = 10;
pub const HTSIZEFIRST: i16 = HTLEFT;
pub const HTRIGHT: i16 = 11;
pub const HTTOP: i16 = 12;
pub const HTTOPLEFT: i16 = 13;
pub const HTTOPRIGHT: i16 = 14;
pub const HTBOTTOM: i16 = 15;
pub const HTBOTTOMLEFT: i16 = 16;
pub const HTBOTTOMRIGHT: i16 = 17;
pub const HTSIZELAST: i16 = HTBOTTOMRIGHT;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WM_MBUTTONDOWN: u32 = 0x0207;
const WM_XBUTTONDOWN: u32 = 0x020b;

/// What the default handler does with one WM_SETCURSOR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetCursorAction {
    /// Beep, then answer FALSE: an error area has no cursor of its own.
    Beep,
    /// An error area with no button-down message answers FALSE in silence.
    None,
    /// Install the class cursor of the named window; a class with no cursor
    /// answers FALSE and leaves the pointer alone.
    ClassCursor,
    /// Load the shared OEM cursor and install it; the answer is the cursor it
    /// replaced, not a boolean.
    OemCursor(u32),
}

/// Hit-test code and originating message decide the action. # C: O(1)
pub const fn set_cursor_action(hit_test: i16, message: u32) -> SetCursorAction {
    match hit_test {
        HTERROR => match message {
            WM_LBUTTONDOWN | WM_MBUTTONDOWN | WM_RBUTTONDOWN | WM_XBUTTONDOWN => SetCursorAction::Beep,
            _ => SetCursorAction::None,
        },
        HTCLIENT => SetCursorAction::ClassCursor,
        HTLEFT | HTRIGHT => SetCursorAction::OemCursor(IDC_SIZEWE),
        HTTOP | HTBOTTOM => SetCursorAction::OemCursor(IDC_SIZENS),
        HTTOPLEFT | HTBOTTOMRIGHT => SetCursorAction::OemCursor(IDC_SIZENWSE),
        HTTOPRIGHT | HTBOTTOMLEFT => SetCursorAction::OemCursor(IDC_SIZENESW),
        _ => SetCursorAction::OemCursor(IDC_ARROW),
    }
}

/// A child gives its parent first refusal everywhere but the resize border.
/// # C: O(1)
pub const fn parent_gets_first_chance(child: bool, parent_is_desktop: bool, hit_test: i16) -> bool {
    child && !parent_is_desktop && (hit_test < HTSIZEFIRST || hit_test > HTSIZELAST)
}

/// Split the WM_SETCURSOR lParam into its hit-test code and the message that
/// produced it. # C: O(1)
pub const fn split_lparam(lparam: u64) -> (i16, u32) { (lparam as u16 as i16, (lparam >> 16) as u16 as u32) }

#[cfg(test)]
#[path = "tests/set_cursor.rs"]
mod tests;
