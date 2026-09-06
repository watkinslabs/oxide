//! Process-scoped adapters for canonical child identifiers.
use super::*;
use ipc::win32_window::LongPtrError;

/// Atomically replace a procedure and its A/W encoding under the canonical GUI lock.
/// # C: O(N_process_gui_states + N_windows)
/// # Lk: GUI; # Ctx: task; # Sleeps: no
pub(crate) fn set_window_long_with_encoding_for_current(hwnd: u64, offset: i32, width: usize,
    value: u64, unicode: bool) -> Result<u64, LongPtrError> {
    let current = sched::live::current().filter(|task| task.is_nt_personality()).ok_or(LongPtrError::InvalidWindow)?;
    let window = valid_window(hwnd).ok_or(LongPtrError::InvalidWindow)?;
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(LongPtrError::InvalidWindow)?;
    entry.state.set_window_long_with_encoding(window, offset, width, value, unicode)
}

/// Query the current process's canonical extra bytes and scalar fields.
/// # C: O(N_process_gui_states + N_windows)
/// # Lk: GUI; # Ctx: task; # Sleeps: no
pub(crate) fn get_window_long_ptr_for_current(hwnd: u64, offset: i32) -> Result<u64, LongPtrError> {
    get_window_long_for_current(hwnd, offset, 8)
}

/// Query a WORD/DWORD/pointer field through its canonical owner. # C: O(N_process_gui_states + N_windows)
pub(crate) fn get_window_long_for_current(hwnd: u64, offset: i32, width: usize) -> Result<u64, LongPtrError> {
    let current = sched::live::current().filter(|task| task.is_nt_personality()).ok_or(LongPtrError::InvalidWindow)?;
    let window = valid_window(hwnd).ok_or(LongPtrError::InvalidWindow)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(LongPtrError::InvalidWindow)?;
    entry.state.get_window_long(window, offset, width)
}

/// Store local state after the caller resolves any A/W procedure value.
/// # C: O(N_process_gui_states + N_windows)
/// # Lk: GUI; # Ctx: task; # Sleeps: no
pub(crate) fn set_window_long_ptr_for_current(hwnd: u64, offset: i32, value: u64) -> Result<u64, LongPtrError> {
    set_window_long_for_current(hwnd, offset, 8, value)
}

/// Replace a width-admitted field; previous zero remains successful. # C: O(N_process_gui_states + N_windows)
pub(crate) fn set_window_long_for_current(hwnd: u64, offset: i32, width: usize, value: u64) -> Result<u64, LongPtrError> {
    let current = sched::live::current().filter(|task| task.is_nt_personality()).ok_or(LongPtrError::InvalidWindow)?;
    let window = valid_window(hwnd).ok_or(LongPtrError::InvalidWindow)?;
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(LongPtrError::InvalidWindow)?;
    entry.state.set_window_long(window, offset, width, value)
}


/// Store a full-width child ID; do not resolve it through the HMENU owner.
/// # C: O(N_process_gui_states + N_windows)
/// # Lk: GUI; # Ctx: task; # Sleeps: no
pub(crate) fn set_control_id_for_current(hwnd: u64, value: u64) -> Result<u64, ()> {
    let current = sched::live::current().filter(|task| task.is_nt_personality()).ok_or(())?;
    let window = valid_window(hwnd).ok_or(())?;
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(())?;
    entry.state.set_control_id(window, value).map_err(|_| ())
}

/// Read the current process's child ID without conflating zero with failure.
/// # C: O(N_process_gui_states + N_windows)
/// # Lk: GUI; # Ctx: task; # Sleeps: no
pub(crate) fn control_id_for_current(hwnd: u64) -> Option<u64> {
    let current = sched::live::current().filter(|task| task.is_nt_personality())?;
    let window = valid_window(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))?;
    entry.state.control_id(window)
}
