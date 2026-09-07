//! Capture, hot keys and thread input attachment for the calling NT process.
use ipc::win32_window::{AttachError, Hotkey, HotkeyError, WindowId};
use super::super::owner::{current_tid, with_state, with_state_mut};
use super::super::valid_window;

/// Optional window argument: zero names no window, and a value outside the
/// handle range is refused. # C: O(1)
fn optional_window(hwnd: u64) -> Option<Option<WindowId>> {
    if hwnd == 0 { return Some(None); }
    valid_window(hwnd).map(Some)
}

/// # C: O(N_nt_processes + N_windows + N_queues)
pub(crate) fn set_capture_for_current(hwnd: u64, flags: u32) -> Option<u64> {
    let window = optional_window(hwnd)?;
    let tid = current_tid()?;
    with_state_mut(|state| state.set_capture_window(tid, window, flags).ok())?
        .map(|previous| previous.map_or(0, |id| id.raw() as u64))
}

/// # C: O(N_nt_processes + N_windows + N_queues)
pub(crate) fn release_capture_for_current() -> bool {
    let Some(tid) = current_tid() else { return false; };
    with_state_mut(|state| state.set_capture_window(tid, None, 0).is_ok()).unwrap_or(false)
}

/// # C: O(N_nt_processes)
pub(crate) fn capture_window_for_current() -> u64 {
    with_state(|state| state.capture_window().map_or(0, |id| id.raw() as u64)).unwrap_or(0)
}

/// # C: O(N_nt_processes + N_windows + N_hotkeys)
pub(crate) fn register_hotkey_for_current(hwnd: u64, id: i32, modifiers: u32, vkey: u32) -> Result<Option<Hotkey>, HotkeyError> {
    let window = optional_window(hwnd).ok_or(HotkeyError::NoSuchWindow)?;
    let tid = current_tid().ok_or(HotkeyError::NoSuchWindow)?;
    with_state_mut(|state| state.register_hotkey(tid, window, id, modifiers, vkey)).ok_or(HotkeyError::NoSuchWindow)?
}

/// # C: O(N_nt_processes + N_windows + N_hotkeys)
pub(crate) fn unregister_hotkey_for_current(hwnd: u64, id: i32) -> Result<Hotkey, HotkeyError> {
    let window = optional_window(hwnd).ok_or(HotkeyError::NoSuchWindow)?;
    let tid = current_tid().ok_or(HotkeyError::NoSuchWindow)?;
    with_state_mut(|state| state.unregister_hotkey(tid, window, id)).ok_or(HotkeyError::NotRegistered)?
}

/// # C: O(N_nt_processes + N_queues)
pub(crate) fn attach_thread_input_for_current(from: u64, to: u64, attach: bool) -> Result<(), AttachError> {
    with_state_mut(|state| state.attach_thread_input(from, to, attach)).unwrap_or(Err(AttachError::InvalidParameter))
}
