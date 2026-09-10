//! Kernel binding: the canonical owner holds the shared cursors and the one
//! cursor the pointer displays.
use super::*;

/// Answer the two cursor ordinals; every other ordinal belongs elsewhere.
/// # C: O(N_process_gui_states + N_cursors)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    match ordinal {
        GET_CURSOR => Some(crate::nt_window::current_cursor_for_current().unwrap_or(0)),
        SET_CURSOR => Some(crate::nt_window::set_current_cursor_for_current(*args.first()?).unwrap_or(0)),
        _ => None,
    }
}

/// Default WM_SETCURSOR handling. # C: O(N_process_gui_states + N_windows + N_classes)
pub(crate) fn apply_default_step(step: SetCursorStep) -> u64 {
    apply_set_cursor(step,
        |hwnd| crate::nt_window::class_cursor_for_current(hwnd).unwrap_or(0),
        |id| crate::nt_window::shared_oem_cursor_for_current(id).unwrap_or(0),
        |cursor| crate::nt_window::set_current_cursor_for_current(cursor).unwrap_or(0))
}
