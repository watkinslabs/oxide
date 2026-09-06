//! Partial paints merge into canonical backing before frame serialization (`31fk`).
use ipc::win32_gdi::{GdiManager, PaintBacking};
use ipc::win32_window::PaintRegion;

/// Exact session coverage is authoritative; caller bounds are only an ABI consistency check. # C: O(frame pixels + region)
pub(crate) fn capture_region(state: &mut GdiManager, hwnd: u32, dc: u32, region: &PaintRegion, layout: PaintBacking)
    -> Result<syscall::nt_compositor::Record, ()> {
    if region.is_empty() { return Err(()); }
    let backing = state.retain_paint_region(hwnd, dc, region, layout).map_err(|_| ())?;
    let (width, height, pixels) = state.surface(backing).ok_or(())?;
    crate::nt_gdi_frame::snapshot(hwnd, 1, width, height, pixels).map_err(|_| ())
}
