//! Canonical control geometry and drawing callback record.
use alloc::sync::Arc;
use ipc::win32_window::WindowId;
use ipc::win32_gdi::{Rect, ScrollLayout, ScrollMetrics};
use crate::nt_window::GUI;
use super::proc_abi::*;

/// # C: O(processes + windows² + scrollbar layout)
pub(super) fn record(hwnd: u64, dc: u64, arrows: bool, interior: bool) -> Option<[u8; DRAW_BYTES]> {
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let window = u32::try_from(hwnd).ok().and_then(WindowId::from_raw)?;
    let (rect, style, state) = {
        let entries = GUI.lock();
        let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        if !entry.state.drawable(window) { return None; }
        let rect = entry.state.client_rect(window)?;
        (Rect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom },
            entry.state.get(window)?.style, entry.state.scroll_control_state(window).ok()?)
    };
    if rect.left >= rect.right || rect.top >= rect.bottom { return None; }
    let size_box = style & (SBS_SIZEBOX | SBS_SIZEGRIP) != 0;
    let vertical = !size_box && style & SBS_VERT != 0;
    let layout = if size_box { ScrollLayout { arrow_size: 0, thumb_pos: 0, thumb_size: 0 } }
        else { ipc::win32_gdi::scrollbar_layout(if vertical { rect.bottom - rect.top } else { rect.right - rect.left },
            state, ScrollMetrics { arrow_size: ipc::win32_gdi::system_metric_default(SM_CXVSCROLL)?, dpi: 96 }).ok()? };
    Some(draw_record(hwnd, dc, rect, layout, state.flags, vertical, arrows, interior))
}
