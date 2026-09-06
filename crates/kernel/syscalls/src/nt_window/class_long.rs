//! Per-process class-long and cursor access. Every decision lives in the
//! canonical class owner; this module only resolves the calling process.
use super::*;
use ipc::win32_window::LongPtrError;

fn with_state_mut<T>(f: impl FnOnce(&mut ipc::win32_window::WindowManager) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index].state))
}

fn with_state<T>(f: impl FnOnce(&ipc::win32_window::WindowManager) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    Some(f(&entry.state))
}

/// # C: O(processes + windows + classes)
pub(crate) fn class_long_for_current(hwnd: u64, offset: i32, width: usize) -> Result<u64, LongPtrError> {
    let Some(id) = valid_window(hwnd) else { return Err(LongPtrError::InvalidWindow); };
    with_state(|state| state.class_long(id, offset, width)).unwrap_or(Err(LongPtrError::InvalidWindow))
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
