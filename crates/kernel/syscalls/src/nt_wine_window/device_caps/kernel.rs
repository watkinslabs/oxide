//! Kernel binding: the GDI object owner resolves the handle, the compositor and
//! the display driver supply the device the capability table describes.
use super::{Device, ORDINAL, caps};

/// Every capability answers an `INT`; an unresolvable device context answers
/// zero rather than a status code. # C: O(processes + objects + monitors)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    let [dc, cap, ..] = args else { return Some(0); };
    Some(answer(*dc, *cap as u32 as i32))
}

/// # C: O(processes + objects + monitors)
fn answer(dc: u64, cap: i32) -> u64 {
    let Ok(dc) = u32::try_from(dc) else { return 0; };
    if !crate::nt_gdi::contains_dc_for_current(dc) { return 0; }
    caps(cap, device()) as i64 as u64
}

/// Read every field from its canonical owner on each call; a desktop that
/// changes resolution changes the reported capabilities with it.
/// # C: O(monitors)
fn device() -> Device {
    let screen = super::super::metrics::screen_size(crate::nt_compositor::monitors_current).unwrap_or((0, 0));
    let desktop = super::super::metrics::virtual_screen_size(crate::nt_compositor::monitors_current).unwrap_or((0, 0));
    Device {
        screen,
        desktop,
        dpi: drm::primary_system_dpi() as i32,
        depth: ipc::win32_gdi::SURFACE_BITS_PER_PIXEL as i32,
        // A true-colour surface realises no palette, so no palette entries exist.
        palette_size: 0,
        refresh_hz: drm::primary_refresh_hz() as i32,
    }
}
