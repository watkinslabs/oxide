//! Copy native text state from the existing process GDI owner.
use super::*;
use ipc::win32_gdi::{GdiError, GdiManager, TextAttribute, TextState};

/// Resolve selected or stock metrics through the canonical owner. # C: O(processes + DCs + fonts)
pub(crate) fn text_metrics_for_current(dc: u64) -> Result<ipc::win32_gdi::TextMetrics, u64> {
    with_dc(dc, |state, dc| state.text_metrics(dc))
}

fn with_dc<R>(dc: u64, action: impl FnOnce(&mut GdiManager, u32) -> Result<R, GdiError>) -> Result<R, u64> {
    let dc = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    let cur = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    if !cur.is_nt_personality() { return Err(STATUS_INVALID_HANDLE); }
    let mut entries = GDI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
        .ok_or(STATUS_INVALID_HANDLE)?;
    action(&mut entry.state, dc).map_err(|error| match error {
        GdiError::NoSuchObject => STATUS_INVALID_HANDLE,
        _ => STATUS_INVALID_PARAMETER,
    })
}

/// No GDI lock or borrowed surface crosses the native callback boundary.
/// # C: O(processes + DCs + fonts)
pub(crate) fn text_snapshot_for_current(dc: u64) -> Result<TextState, u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let (mut state, binding) = snapshot_binding(dc)?;
    if let Some(binding) = binding {
        let shared = binding.text_snapshot(dc as u32).map_err(|_| STATUS_INVALID_PARAMETER)?;
        state.attributes = ipc::win32_gdi::TextAttributes { foreground: shared.foreground, background: shared.background,
            background_mode: shared.background_mode, alignment: shared.alignment, current_position: shared.current_position };
    }
    Ok(state)
}

pub(super) fn snapshot_binding(dc: u64) -> Result<(TextState, Option<client::ClientBinding>), u64> {
    let dc = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    let cur = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    if !cur.is_nt_personality() { return Err(STATUS_INVALID_HANDLE); }
    let entries = GDI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
    Ok((entry.state.text_state(dc).map_err(|_| STATUS_INVALID_HANDLE)?, entry.client))
}

/// Colors supplied by the adapter are already normalized to XRGB. # C: O(processes + DCs)
pub(crate) fn set_text_attribute_for_current(dc: u64, attribute: TextAttribute, value: u32) -> Result<u32, u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    if let (_, Some(binding)) = snapshot_binding(dc)? {
        let field = match attribute { TextAttribute::Foreground => 0, TextAttribute::Background => 1,
            TextAttribute::BackgroundMode => 2, TextAttribute::Alignment => 3 };
        return binding.set_text_attribute(dc as u32, field, value).map_err(|_| STATUS_INVALID_PARAMETER);
    }
    with_dc(dc, |state, dc| state.set_text_attribute(dc, attribute, value))
}

/// Current-position updates never create another device-context record. # C: O(processes + DCs)
pub(crate) fn set_text_position_for_current(dc: u64, position: (i32, i32)) -> Result<(i32, i32), u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    if let (_, Some(binding)) = snapshot_binding(dc)? {
        return binding.set_text_position(dc as u32, position).map_err(|_| STATUS_INVALID_PARAMETER);
    }
    with_dc(dc, |state, dc| state.set_text_position(dc, position))
}

/// Validate and copy glyph bytes without the GDI lock, then blend atomically
/// into that process's existing DC. # C: O(source pixels + processes + DCs)
pub(crate) fn blend_surface_for_current(dc: u64, source: u64, x: i32, y: i32, width: u32, height: u32) -> u64 {
    if dc > u32::MAX as u64 { return STATUS_INVALID_HANDLE; }
    let Some(count) = (width as usize).checked_mul(height as usize)
        .filter(|count| *count > 0 && *count <= 16 * 1024 * 1024) else { return STATUS_INVALID_PARAMETER; };
    let Some(bytes) = count.checked_mul(4) else { return STATUS_INVALID_PARAMETER; };
    if source == 0 || source.checked_add(bytes as u64).is_none() { return STATUS_INVALID_PARAMETER; }
    let mut pixels = Vec::<u32>::new();
    if pixels.try_reserve_exact(count).is_err() { return 0xc000_0017; }
    pixels.resize(count, 0);
    // SAFETY: the initialized u32 allocation owns exactly bytes mutable bytes;
    // every bit pattern is valid and no reference to its elements is retained.
    let destination = unsafe { core::slice::from_raw_parts_mut(pixels.as_mut_ptr().cast::<u8>(), bytes) };
    if uaccess::copy_from_user(destination, source).is_err() { return STATUS_INVALID_PARAMETER; }
    match with_dc(dc, |state, dc| state.blend_pixels(dc, x, y, width, height, &pixels)) {
        Ok(()) => STATUS_SUCCESS, Err(status) => status,
    }
}
