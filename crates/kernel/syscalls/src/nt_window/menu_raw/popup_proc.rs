//! The builtin popup-menu class window procedure: which message it answers
//! itself and with what, and which it leaves to the default procedure.

/// The popup-menu class answers this message with the menu it shows.
pub(crate) const MN_GETHMENU: u32 = 0x01e1;
/// A popup menu takes no activation when it is clicked.
pub(crate) const MA_NOACTIVATE: u64 = 3;
/// The popup-menu class draws its own background, so erasing is answered.
pub(crate) const ERASE_HANDLED: u64 = 1;

const WM_CREATE: u32 = 0x0001;
const WM_DESTROY: u32 = 0x0002;
const WM_PAINT: u32 = 0x000f;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_SHOWWINDOW: u32 = 0x0018;
const WM_MOUSEACTIVATE: u32 = 0x0021;
const WM_PRINTCLIENT: u32 = 0x0318;

/// What the popup-menu window procedure does with one message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PopupProcAction {
    /// Retain the menu named by the creation parameters on the window.
    StoreMenu,
    /// Refuse activation.
    NoActivate,
    /// Paint the menu the window carries into its own update region.
    Paint,
    /// Paint the menu into the caller's device context.
    PrintClient,
    /// The background needs no separate erase.
    EraseHandled,
    /// The session's window is going away.
    Destroyed,
    /// Being hidden drops the menu the window carries; being shown keeps it.
    Shown(bool),
    /// Report the menu the window carries.
    ReportMenu,
    /// Everything else is the default procedure's.
    Default,
}

/// # C: O(1)
pub(crate) fn popup_proc_action(message: u32, wparam: u64) -> PopupProcAction {
    match message {
        WM_CREATE => PopupProcAction::StoreMenu,
        WM_MOUSEACTIVATE => PopupProcAction::NoActivate,
        WM_PAINT => PopupProcAction::Paint,
        WM_PRINTCLIENT => PopupProcAction::PrintClient,
        WM_ERASEBKGND => PopupProcAction::EraseHandled,
        WM_DESTROY => PopupProcAction::Destroyed,
        WM_SHOWWINDOW => PopupProcAction::Shown(wparam != 0),
        MN_GETHMENU => PopupProcAction::ReportMenu,
        _ => PopupProcAction::Default,
    }
}

#[cfg(test)]
#[path = "../tests/menu_popup_proc.rs"]
mod tests;
