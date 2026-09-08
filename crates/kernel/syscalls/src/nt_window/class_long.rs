//! Per-process class-long and cursor access. Every decision lives in the
//! canonical class owner; this module only resolves the calling process.
use super::*;
use ipc::win32_window::LongPtrError;
use super::owner::{with_state, with_state_mut};

/// # C: O(processes + windows + classes)
pub(crate) fn class_long_for_current(hwnd: u64, offset: i32, width: usize) -> Result<u64, LongPtrError> {
    let Some(id) = valid_window(hwnd) else { return Err(LongPtrError::InvalidWindow); };
    with_state(|state| state.class_long_for(id, offset, width)).unwrap_or(Err(LongPtrError::InvalidWindow))
}

/// Exchange the client menu-name handle of a window the calling process owns.
/// # C: O(processes + windows + classes)
pub(crate) fn exchange_class_menu_name_for_current(hwnd: u64, menu_name: u64) -> Result<u64, LongPtrError> {
    let Some(id) = valid_window(hwnd) else { return Err(LongPtrError::InvalidWindow); };
    with_state_mut(|state| state.exchange_class_menu_name(id, menu_name)).unwrap_or(Err(LongPtrError::InvalidWindow))
}

/// # C: O(processes + windows + classes)
pub(crate) fn set_class_long_for_current(hwnd: u64, offset: i32, value: u64, width: usize) -> Result<u64, LongPtrError> {
    let Some(id) = valid_window(hwnd) else { return Err(LongPtrError::InvalidWindow); };
    with_state_mut(|state| state.set_class_long(id, offset, value, width)).unwrap_or(Err(LongPtrError::InvalidWindow))
}

/// Class cursor of a window the calling process owns. # C: O(processes + windows + classes)
pub(crate) fn class_cursor_for_current(hwnd: u64) -> Option<u64> {
    let id = valid_window(hwnd)?;
    with_state(|state| state.class_cursor(id)).flatten()
}

/// Load one shared OEM cursor into the calling process. # C: O(processes + cursors)
pub(crate) fn shared_oem_cursor_for_current(id: u32) -> Option<u64> {
    with_state_mut(|state| state.shared_oem_cursor(id).ok()).flatten()
}

/// # C: O(processes + cursors)
pub(crate) fn set_current_cursor_for_current(handle: u64) -> Option<u64> {
    with_state_mut(|state| state.set_current_cursor(handle).ok()).flatten()
}

/// # C: O(processes)
pub(crate) fn current_cursor_for_current() -> Option<u64> { with_state(|state| state.current_cursor()) }
