//! Canonical whole-surface and paint-region capture with one publication reservation.
use super::{output, paint_frame, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};

/// Whole-surface retention and output reservation share caller GDI ownership. # C: O(DCs + pixels)
pub(super) fn capture_window(state: &mut ipc::win32_gdi::GdiManager, hwnd: u32, dc: u32, window: Option<(ipc::win32_window::WindowRect, bool)>) -> Result<output::PreparedFrame, u64> {
    let (bounds, _visible) = window.ok_or(STATUS_INVALID_HANDLE)?;
    if bounds.right <= bounds.left || bounds.bottom <= bounds.top { return Err(STATUS_INVALID_PARAMETER); }
    let (width, height, _) = state.surface(dc).ok_or(STATUS_INVALID_HANDLE)?;
    let backing = state.window_dc(hwnd).ok_or(STATUS_INVALID_HANDLE)?;
    if backing != dc {
        let rect = ipc::win32_gdi::Rect { left: 0, top: 0, right: width, bottom: height };
        state.retain_paint(hwnd, dc, rect, ipc::win32_gdi::PaintBacking { width, height, client: rect })
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
    }
    // Hidden windows may paint during WM_CREATE. The backend retains the
    // frame without mapping the window until the canonical visibility changes.
    output::prepare_explicit(state, hwnd, backing).map_err(|_| STATUS_INVALID_PARAMETER)
}

/// Exact canonical paint coverage is validated before the merge. The paint's
/// pixels join the window backing and its coverage becomes pending output; the
/// message pump flushes it with whatever else the burst drew, which is what the
/// reference's window surface does with its accumulated bounds.
/// # C: O(DCs + damage pixels + region)
pub(super) fn merge_window_region(state: &mut ipc::win32_gdi::GdiManager, hwnd: u32, dc: u32, left: i32, top: i32, right: i32, bottom: i32, snapshot: Option<(ipc::win32_gdi::PaintBacking, ipc::win32_window::PaintRegion)>) -> Result<(), u64> {
    let (layout, region) = snapshot.ok_or(STATUS_INVALID_HANDLE)?;
    if region.bounds() != Some(ipc::win32_window::WindowRect { left, top, right, bottom }) { return Err(STATUS_INVALID_PARAMETER); }
    paint_frame::merge_region(state, hwnd, dc, &region, layout).map_err(|_| STATUS_INVALID_PARAMETER)?;
    Ok(())
}
