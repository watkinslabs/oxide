//! Live binding for the builtin popup-menu window procedure: the class stores
//! the menu it shows on the window, paints it, and reports it on request.
use super::entry::with_entry;
use super::popup_proc::{popup_proc_action, PopupProcAction, ERASE_HANDLED, MA_NOACTIVATE};
use super::popup_window::POPUP_MENU_EXTRA_OFFSET;
use ipc::win32_window::WindowId;

/// The window the popup-menu class carries its menu on. # C: O(1)
fn window_of(hwnd: u64) -> Option<WindowId> { u32::try_from(hwnd).ok().and_then(WindowId::from_raw) }

/// The menu one popup-menu window shows. # C: O(N_windows)
fn menu_of_window(hwnd: u64) -> u64 {
    let Some(window) = window_of(hwnd) else { return 0; };
    with_entry(|entry| entry.state.get_window_long_ptr(window, POPUP_MENU_EXTRA_OFFSET).unwrap_or(0)).unwrap_or(0)
}

/// The creation parameter a `CREATESTRUCTW` carries, which the popup-menu
/// class stores as its menu. # C: O(1) plus bounded usercopy
fn create_params(lparam: u64) -> u64 {
    if lparam == 0 { return 0; }
    uaccess::get_user_u64(lparam).unwrap_or(0)
}

/// Run the popup-menu class procedure for one message.
/// # C: O(N_windows); # Sleeps: yes
pub(crate) fn popup_menu_window_proc(hwnd: u64, message: u32, wparam: u64, lparam: u64) -> u64 {
    match popup_proc_action(message, wparam) {
        PopupProcAction::StoreMenu => {
            let menu = create_params(lparam);
            if let Some(window) = window_of(hwnd).filter(|_| menu != 0) {
                with_entry(|entry| { let _ = entry.state.set_window_long_ptr(window, POPUP_MENU_EXTRA_OFFSET, menu); });
            }
            0
        }
        PopupProcAction::NoActivate => MA_NOACTIVATE,
        PopupProcAction::EraseHandled => ERASE_HANDLED,
        // The class background paints the popup; the menu's items are drawn
        // over it by the same paint transaction every window uses.
        PopupProcAction::Paint | PopupProcAction::PrintClient => crate::nt_window::default_paint::for_current(hwnd),
        PopupProcAction::Destroyed => 0,
        PopupProcAction::Shown(shown) => {
            if !shown { if let Some(window) = window_of(hwnd) { with_entry(|entry| { let _ = entry.state.set_window_long_ptr(window, POPUP_MENU_EXTRA_OFFSET, 0); }); } }
            0
        }
        PopupProcAction::ReportMenu => menu_of_window(hwnd),
        PopupProcAction::Default => crate::nt_window::dispatch(syscall::nt::NtCall { service: syscall::nt::NtService::DefaultWindowProc,
            args: syscall::SyscallArgs { a0: hwnd, a1: message as u64, a2: wparam, a3: lparam, a4: 0, a5: 0 } }).unwrap_or(0),
    }
}
