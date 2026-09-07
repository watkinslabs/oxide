//! Process binding for bitmap, DIB, palette and blit work; usercopy stays
//! outside the owner lock and every raster decision belongs to the owner.
use super::*;
use ipc::win32_gdi::{GdiError, GdiManager, Rgb, SharedDcColors};

fn status(error: lifecycle::LifecycleError<GdiError>) -> u64 {
    match error {
        lifecycle::LifecycleError::Canonical(GdiError::NoSuchObject) => STATUS_INVALID_HANDLE,
        lifecycle::LifecycleError::Canonical(_) => STATUS_INVALID_PARAMETER,
        _ => STATUS_INVALID_HANDLE,
    }
}

/// Run one owner action against the current process's canonical objects. # C: O(processes)
pub(crate) fn with_gdi<R>(action: impl FnOnce(&mut GdiManager) -> Result<R, GdiError>) -> Result<R, u64> {
    brush::with_owner(action)
}

/// The device-context colours and stretch mode a raster operation consumes.
/// A bound client owns them in shared memory, so they are read there and never
/// mirrored in the owner. An unbound process falls back to the owner's own
/// attributes. # C: O(processes)
pub(crate) fn dc_state(dc: u64) -> Result<(Option<SharedDcColors>, u32), u64> {
    let (_, binding) = text::snapshot_binding(dc)?;
    let handle = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    let Some(binding) = binding else { return Ok((None, ipc::win32_gdi::BLACKONWHITE)); };
    let bytes = binding.read_dc_attr(handle).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let colors = brush::shared::colors(&bytes).map_err(|_| STATUS_INVALID_PARAMETER)?;
    Ok((Some(colors), brush::shared::stretch_mode(&bytes)))
}

/// Owner-held colours for a process whose client is not bound yet. # C: O(processes + DCs)
pub(crate) fn owner_colors(dc: u32) -> Result<SharedDcColors, u64> {
    with_gdi(|state| {
        let text = state.text_state(dc)?;
        let brush = state.dc_brush_color(dc)?;
        Ok(SharedDcColors { brush, text: text.attributes.foreground, background: text.attributes.background,
            background_mode: text.attributes.background_mode })
    })
}

/// Resolve the colours a raster operation uses, preferring the client's own
/// record. # C: O(processes + DCs)
pub(crate) fn colors_for(dc: u64) -> Result<(SharedDcColors, u32), u64> {
    let (shared, mode) = dc_state(dc)?;
    let handle = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    match shared { Some(colors) => Ok((colors, mode)), None => Ok((owner_colors(handle)?, mode)) }
}

/// # C: O(processes + width*height)
pub(crate) fn create_compatible_bitmap_for_current(dc: u32, width: i32, height: i32, planes: u32, bpp: u32) -> Result<u32, u64> {
    lifecycle::create_object_for_current(
        |state| state.create_compatible_bitmap(dc, width, height, planes, bpp),
        |state, handle| state.delete_bitmap(handle)).map_err(status)
}

/// The header, colour table and masks are already fetched: usercopy may fault
/// and must not run under the owner lock. # C: O(processes + width*height)
pub(crate) fn create_dib_section_for_current(header: ipc::win32_gdi::DibHeader, usage: u32, table: &[Rgb], masks: [u32; 3]) -> Result<u32, u64> {
    lifecycle::create_object_for_current(
        |state| state.create_dib_section(header, usage, table, masks),
        |state, handle| state.delete_bitmap(handle)).map_err(status)
}

/// # C: O(processes)
pub(crate) fn create_hatch_brush_for_current(style: u32, color: u32) -> Result<u32, u64> {
    lifecycle::create_object_for_current(
        |state| state.create_hatch_brush(style, color),
        |state, handle| state.delete_brush(handle)).map_err(status)
}

/// # C: O(processes + entries)
pub(crate) fn create_palette_for_current(version: u16, entries: &[ipc::win32_gdi::PaletteEntry]) -> Result<u32, u64> {
    lifecycle::create_object_for_current(
        |state| state.create_palette(version, entries),
        |state, handle| state.delete_palette(handle)).map_err(status)
}

/// # C: O(processes + entries)
pub(crate) fn create_halftone_palette_for_current() -> Result<u32, u64> {
    lifecycle::create_object_for_current(
        |state| state.create_halftone_palette(),
        |state, handle| state.delete_palette(handle)).map_err(status)
}

/// Selection can retire a handle that was deleted while selected, so the
/// client projection drops it in the same transaction. # C: O(processes + DCs + bitmaps)
pub(crate) fn select_bitmap_for_current(dc: u64, bitmap: u64) -> Result<u32, u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let (_, binding) = text::snapshot_binding(dc)?;
    let dc = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    let bitmap = u32::try_from(bitmap).map_err(|_| STATUS_INVALID_HANDLE)?;
    let (previous, live) = with_gdi(|state| {
        let previous = state.select_bitmap(dc, bitmap)?;
        Ok((previous, previous == 0 || state.contains_object(previous)))
    })?;
    if !live {
        if let Some(binding) = binding { binding.delete_handle(previous).map_err(|_| STATUS_INVALID_PARAMETER)?; }
    }
    Ok(previous)
}
