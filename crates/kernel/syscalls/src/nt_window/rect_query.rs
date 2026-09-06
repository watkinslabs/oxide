//! Live current-process wrapper for the canonical GetWindowRects policy.

use super::*;
#[path = "rect_query/policy.rs"]
mod policy;
pub(crate) use policy::{map_rect, query_state, RectKind};

pub(crate) fn query_current(hwnd: u32, client: bool, requested_dpi: u32)
    -> Option<ipc::win32_window::WindowRect>
{
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let source_dpi = drm::primary_system_dpi();
    let group = alloc::sync::Arc::clone(&cur.thread_group);
    let window = ipc::win32_window::WindowId::from_raw(hwnd)?;
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade()
        .is_some_and(|candidate| alloc::sync::Arc::ptr_eq(&candidate, &group)))?;
    query_state(&entries[index].state, window,
        if client { RectKind::Client } else { RectKind::Window }, requested_dpi, source_dpi)
}
