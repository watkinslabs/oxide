//! Snapshot canonical window/class/visibility state before entering GDI ownership.
use super::*;

/// No GDI lock, usercopy or callback under GUI ownership. # C: O(processes + windows² + regions²)
pub(crate) fn dc_lease_context_for_current(hwnd: u32, flags: u32) -> Option<ipc::win32_window::DcLeaseContext> {
    let current = sched::live::current().filter(|task| task.is_nt_personality())?;
    // HWND zero names the desktop, not "no window". Resolving it through the
    // published desktop root is what lets a startup GetDC(0) — the usual way an
    // application measures text before it has a window of its own — return a
    // real DC instead of NULL.
    let window = match hwnd {
        0 => {
            let target = super::desktop::resolve_for_current()?;
            // The root's backing lives in the root's own GDI state. Leasing it
            // from this process's entry would hand back another process's
            // handles, so a cross-process desktop DC is refused here rather
            // than answered wrongly (KI-0424).
            if !Arc::ptr_eq(&target.group, &current.thread_group) { return None; }
            target.window
        }
        _ => ipc::win32_window::WindowId::from_raw(hwnd)?,
    };
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))?;
    entry.state.dc_lease_context(window, flags).ok()
}
