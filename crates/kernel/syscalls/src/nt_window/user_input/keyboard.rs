//! Active keyboard layout of the calling thread.
use alloc::vec::Vec;
use ipc::win32_window::LayoutError;
use super::super::owner::{current_tid, with_state, with_state_mut};

/// # C: O(N_nt_processes + N_layouts)
pub(crate) fn keyboard_layout_for_current(thread_id: u32) -> u64 {
    let Some(tid) = current_tid() else { return 0; };
    let tid = if thread_id == 0 { tid } else { thread_id as u64 };
    with_state(|state| state.keyboard_layout(tid)).unwrap_or(0)
}

/// # C: O(N_nt_processes + N_layouts + N_windows)
pub(crate) fn activate_keyboard_layout_for_current(layout: u64) -> Result<u64, LayoutError> {
    let tid = current_tid().ok_or(LayoutError::NotImplemented)?;
    with_state_mut(|state| state.activate_keyboard_layout(tid, layout)).unwrap_or(Err(LayoutError::NotImplemented))
}

/// # C: O(N_nt_processes + N_layouts)
pub(crate) fn keyboard_layout_list_for_current() -> Vec<u64> {
    with_state(|state| state.keyboard_layout_list()).unwrap_or_default()
}

/// Message-time key state of the calling thread, which the character
/// translation reads. # C: O(N_nt_processes + N_queues)
pub(crate) fn keyboard_state_snapshot_for_current() -> Option<[u8; 256]> {
    let tid = current_tid()?;
    with_state(|state| state.keyboard_state(tid))
}
