//! Whether the window manager is allowed to manage a window.
//!
//! An unmanaged window is created override-redirect: the window manager gives
//! it no frame, no title bar, no placement of its own and never moves the input
//! focus to it. That is what a dropdown menu is — a bare popup that appears
//! under the item that opened it — and it is also why the same window framed as
//! a dialog looks wrong.

use crate::styles::{WS_CAPTION, WS_CHILD, WS_EX_APPWINDOW, WS_POPUP, WS_SYSMENU, WS_THICKFRAME};

/// Everything the decision reads, at one position change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Managed {
    pub style: u32,
    pub ex_style: u32,
    /// The position change activates the window: it asks neither to leave
    /// activation alone nor to hide.
    pub activating: bool,
    /// The window is already the active one.
    pub active: bool,
    pub fullscreen: bool,
    /// The window owns at least one popup.
    pub owns_popups: bool,
}

impl Managed {
    /// # C: O(1)
    pub fn is_managed(&self) -> bool {
        // A child window is drawn inside its parent and is never the window
        // manager's. WS_POPUP alongside WS_CHILD makes the window a popup.
        if self.style & (WS_CHILD | WS_POPUP) == WS_CHILD { return false; }
        if self.activating || self.active { return true; }
        if self.style & WS_CAPTION == WS_CAPTION { return true; }
        if self.style & WS_THICKFRAME != 0 { return true; }
        // A popup is managed once it carries a system menu, which is a caption
        // in all but name, and when it covers the whole screen.
        if self.style & WS_POPUP != 0 && (self.style & WS_SYSMENU != 0 || self.fullscreen) { return true; }
        if self.ex_style & WS_EX_APPWINDOW != 0 { return true; }
        self.owns_popups
    }
}

/// The decision a window makes as it is created: creation does not activate the
/// window, a window that does not yet exist is neither the active one nor the
/// owner of a popup, and its extent is not yet a screen's.
/// # C: O(1)
pub fn at_creation(style: u32, ex_style: u32) -> bool {
    Managed { style, ex_style, activating: false, active: false, fullscreen: false, owns_popups: false }.is_managed()
}

#[cfg(test)]
#[path = "tests/managed.rs"]
mod tests;
