//! Snapshot canonical window/class/visibility state before entering GDI ownership.
use super::*;

/// No GDI lock, usercopy or callback under GUI ownership. # C: O(processes + windows² + regions²)
pub(crate) fn dc_lease_context_for_current(hwnd: u32, flags: u32) -> Option<ipc::win32_window::DcLeaseContext> {
    let current = sched::live::current().filter(|task| task.is_nt_personality())?;
    let window = ipc::win32_window::WindowId::from_raw(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))?;
    entry.state.dc_lease_context(window, flags).ok()
}
