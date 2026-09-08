//! Snapshot canonical window/class/visibility state before entering GDI ownership.
use super::*;

/// No GDI lock, usercopy or callback under GUI ownership. # C: O(processes + windows² + regions²)
pub(crate) fn dc_lease_context_for_current(hwnd: u32, flags: u32) -> Option<ipc::win32_window::DcLeaseContext> {
    let current = sched::live::current().filter(|task| task.is_nt_personality())?;
    // HWND zero names the desktop, not "no window". The desktop belongs to
    // no process, so its lease is built from the desktop's own rectangle
    // rather than leased out of some process's window manager: refusing it
    // outside the process that had published the root left a startup
    // GetDC(0) — the usual way an application measures text before it has a
    // window — returning NULL in every other process, a second instance of
    // the same application included (KI-0424).
    if hwnd == 0 || ipc::win32_window::handle_space::is_server_handle(hwnd) {
        let desktop = super::desktop::resolve_for_current()?;
        if hwnd != 0 && hwnd != desktop { return None; }
        let rect = crate::nt_wine_window::metrics::virtual_screen_rect(crate::nt_compositor::monitors_current)?;
        return ipc::win32_window::DcLeaseContext::desktop(desktop, rect).ok();
    }
    let window = ipc::win32_window::WindowId::from_raw(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))?;
    entry.state.dc_lease_context(window, flags).ok()
}
