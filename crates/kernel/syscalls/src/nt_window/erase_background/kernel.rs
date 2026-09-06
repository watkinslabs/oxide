//! Kernel binding: class brush lookup, clip box, select, PatBlt, restore.
use super::*;
use ipc::win32_gdi::{Rect, SystemColor};

fn system_brush(index: u32) -> Option<u32> {
    let role = SystemColor::from_index(index)?;
    crate::nt_gdi::system_color_brush_for_current(role).ok()
}

/// Called by default-procedure dispatch outside GUI/GDI locks. None means the
/// message is not an erase; Some(0) means the class does not erase.
/// # C: O(processes + windows + classes + DCs + pixels)
pub(crate) fn for_current(message: u32, hwnd: u64, dc: u64) -> Option<u64> {
    if !is_erase_message(message) { return None; }
    let Some((background, class_style, client)) = crate::nt_window::class_background_for_current(hwnd) else { return Some(0); };
    let Some(brush) = brush_for(background, system_brush) else { return Some(0); };
    let rect = if fills_client_rect(class_style) {
        let client = client?;
        Rect { left: 0, top: 0, right: client.right - client.left, bottom: client.bottom - client.top }
    } else {
        let Ok((_, rect)) = crate::nt_gdi::app_clip_box_snapshot_for_current(dc) else { return Some(0); };
        rect
    };
    let Ok(previous) = crate::nt_gdi::select_brush_for_current(dc, u64::from(brush)) else { return Some(0); };
    let _ = crate::nt_gdi::pat_blt_for_current(dc, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, PATCOPY);
    if previous != 0 { let _ = crate::nt_gdi::select_brush_for_current(dc, u64::from(previous)); }
    Some(1)
}
