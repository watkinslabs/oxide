//! Live current-process wrapper for the canonical GetWindowRects policy.

use super::*;
#[path = "rect_query/policy.rs"]
mod policy;
pub(crate) use policy::{map_rect, query_state, RectKind};

pub(crate) fn query_current(hwnd: u32, kind: RectKind, requested_dpi: u32)
    -> Option<ipc::win32_window::WindowRect>
{
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    // The desktop window belongs to the desktop, not to a process, so no
    // process's window manager holds a record for it. Its rectangle is the
    // desktop's own, and both the window and the client rectangle are it.
    if ipc::win32_window::handle_space::is_server_handle(hwnd) {
        if super::desktop::resolve_for_current() != Some(hwnd) { return None; }
        return crate::nt_wine_window::metrics::virtual_screen_rect(crate::nt_compositor::monitors_current);
    }
    let source_dpi = drm::primary_system_dpi();
    let group = alloc::sync::Arc::clone(&cur.thread_group);
    let window = ipc::win32_window::WindowId::from_raw(hwnd)?;
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade()
        .is_some_and(|candidate| alloc::sync::Arc::ptr_eq(&candidate, &group)))?;
    query_state(&entries[index].state, window, kind, requested_dpi, source_dpi)
}
