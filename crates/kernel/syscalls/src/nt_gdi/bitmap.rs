//! Process binding for canonical bitmap objects and the brushes that pattern from them.
use super::*;
use ipc::win32_gdi::GdiError;

fn status(error: lifecycle::LifecycleError<GdiError>) -> u64 {
    match error {
        lifecycle::LifecycleError::Canonical(GdiError::NoSuchObject) => STATUS_INVALID_HANDLE,
        lifecycle::LifecycleError::Canonical(_) => STATUS_INVALID_PARAMETER,
        _ => STATUS_INVALID_HANDLE,
    }
}

/// Caller bits are already fetched: usercopy may fault and must not run under
/// the owner lock. # C: O(processes + bitmap bytes)
pub(crate) fn create_bitmap_for_current(width: i32, height: i32, planes: u32, bpp: u32, bits: Option<&[u8]>) -> Result<u32, u64> {
    lifecycle::create_object_for_current(
        |state| state.create_bitmap(width, height, planes, bpp, bits),
        |state, handle| state.delete_bitmap(handle)).map_err(status)
}

/// The brush takes its own copy of the bits, so the source bitmap stays the
/// caller's to delete. # C: O(processes + pattern pixels)
pub(crate) fn create_pattern_brush_for_current(bitmap: u32) -> Result<u32, u64> {
    lifecycle::create_object_for_current(
        |state| state.create_pattern_brush(bitmap),
        |state, handle| state.delete_brush(handle)).map_err(status)
}

/// A display DC covers the whole virtual screen and is the caller's to delete,
/// unlike the cached window leases GetDC hands out.
/// # C: O(processes + surface pixels)
pub(crate) fn create_display_dc_for_current(width: i32, height: i32) -> Result<u32, u64> {
    lifecycle::create_dc_for_current(width, height).map_err(status)
}
