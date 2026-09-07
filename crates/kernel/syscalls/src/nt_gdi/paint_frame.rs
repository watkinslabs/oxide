//! Partial paints merge into canonical backing before frame serialization (`31fk`).
use ipc::win32_gdi::{GdiManager, PaintBacking};
use ipc::win32_window::PaintRegion;

/// Merge one paint's coverage into the canonical window backing and record it
/// as pending output. Nothing is serialized and nothing is sent: the reference
/// lets drawing accumulate a surface's damage bounds and leaves the flush to
/// the message pump, so the paints of one burst reach the display together.
/// Returns the backing the coverage landed in. # C: O(damage pixels + region)
pub(crate) fn merge_region(state: &mut GdiManager, hwnd: u32, dc: u32, region: &PaintRegion, layout: PaintBacking)
    -> Result<u32, ()> {
    if region.is_empty() { return Err(()); }
    state.retain_paint_region(hwnd, dc, region, layout).map_err(|_| ())
}

/// Exact session coverage is authoritative; caller bounds are only an ABI consistency check. # C: O(frame pixels + region)
pub(crate) fn capture_region(state: &mut GdiManager, hwnd: u32, dc: u32, region: &PaintRegion, layout: PaintBacking)
    -> Result<syscall::nt_compositor::Record, ()> {
    if region.is_empty() { return Err(()); }
    let backing = state.retain_paint_region(hwnd, dc, region, layout).map_err(|_| ())?;
    // The merge placed client-origin coverage at the client offset inside the
    // window backing, so the damage the display is given is that coverage in
    // backing coordinates, not the whole surface.
    let damage = crate::nt_gdi_frame::client_damage(region.bounds().ok_or(())?, layout.client).ok_or(())?;
    let (width, height, pixels) = state.surface(backing).ok_or(())?;
    crate::nt_gdi_frame::snapshot(hwnd, 1, width, height, pixels, damage).map_err(|_| ())
}
