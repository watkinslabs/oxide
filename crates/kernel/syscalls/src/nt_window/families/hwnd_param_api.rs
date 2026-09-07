//! The window-owner reads and writes `NtUserCallHwndParam` needs: coordinate
//! mapping, the descriptive record, thread ownership, the child test and the
//! two private-region accesses. Every decision is the owner's; this module
//! resolves the caller and converts handles.
use super::super::*;
use ipc::win32_window::{LongPtrError, WindowId};

fn id(hwnd: u64) -> Option<WindowId> { valid_window(hwnd) }

/// Map points from one window's client space to another's, with the desktop
/// named by a zero handle. Answers the packed offset the client expects, or
/// nothing when either window is unresolvable. # C: O(N_processes + N_windows + N_points)
pub(crate) fn map_points_for_current(from: u64, to: u64, points: &mut [(i32, i32)]) -> Option<u32> {
    let from = if from == 0 { None } else { Some(id(from)?) };
    let to = if to == 0 { None } else { Some(id(to)?) };
    access::with_state(|state| state.map_points(from, to, points))?
}

/// Everything a descriptive window record reports, with both rectangles left
/// in the window's own space for the caller to place. # C: O(N_processes + N_windows)
pub(crate) fn window_info_for_current(hwnd: u64) -> Option<(u32, u32, bool, u16)> {
    let window = id(hwnd)?;
    access::with_state(|state| {
        let record = state.get(window)?;
        Some((record.style, record.ex_style, state.active_window() == Some(window), record.class_atom.unwrap_or(0)))
    })?
}

/// GetWindow, answering the related window's handle or zero.
/// # C: O(N_processes + N_windows²)
pub(crate) fn window_relative_for_current(hwnd: u64, relationship: u32) -> u64 {
    let Some(window) = id(hwnd) else { return 0; };
    access::with_state(|state| state.window_relative(window, relationship))
        .flatten().map_or(0, |found| found.raw() as u64)
}

/// IsChild, which is false for a window that is not a child at all.
/// # C: O(N_processes + N_windows²)
pub(crate) fn is_child_for_current(parent: u64, child: u64) -> bool {
    let (Some(parent), Some(child)) = (id(parent), id(child)) else { return false; };
    access::with_state(|state| state.is_child(parent, child)).unwrap_or(false)
}

/// A window's client-area size, which a layout mirror is measured against.
/// # C: O(N_processes + N_windows)
pub(crate) fn client_size_for_current(hwnd: u64) -> Option<(i32, i32)> {
    let window = id(hwnd)?;
    access::with_state(|state| {
        let rect = state.client_rect(window)?;
        Some((rect.right.saturating_sub(rect.left), rect.bottom.saturating_sub(rect.top)))
    })?
}

/// Read one slot of a window's private extra region. # C: O(N_processes + N_windows)
pub(crate) fn private_data_for_current(hwnd: u64, offset: i32, width: usize) -> Result<u64, LongPtrError> {
    let Some(window) = id(hwnd) else { return Err(LongPtrError::InvalidWindow); };
    access::with_state(|state| state.get_window_long_internal(window, offset, width))
        .unwrap_or(Err(LongPtrError::InvalidWindow))
}

/// Write one slot of a window's private extra region, answering its old value.
/// # C: O(N_processes + N_windows)
pub(crate) fn set_private_data_for_current(hwnd: u64, offset: i32, width: usize, value: u64) -> Result<u64, LongPtrError> {
    let Some(window) = id(hwnd) else { return Err(LongPtrError::InvalidWindow); };
    access::with_state_mut(|state| state.set_window_long_internal(window, offset, width, value))
        .unwrap_or(Err(LongPtrError::InvalidWindow))
}

/// Hand one window its dialog state pointer. # C: O(N_processes + N_windows)
pub(crate) fn set_dialog_info_for_current(hwnd: u64, info: u64) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    access::with_state_mut(|state| state.set_dialog_info(window, info).is_ok()).unwrap_or(false)
}

/// Mark one window an MDI client. # C: O(N_processes + N_windows)
pub(crate) fn mark_mdi_client_for_current(hwnd: u64) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    access::with_state_mut(|state| state.mark_mdi_client(window).is_ok()).unwrap_or(false)
}
