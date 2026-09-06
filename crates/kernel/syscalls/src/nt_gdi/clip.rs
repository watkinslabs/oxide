//! Process/DC admission for clip operations; output copy follows owner lock release.
use super::*;
use ipc::win32_gdi::{Rect, CLIP_ERROR};

/// Transfer admitted exact coverage after the GUI snapshot lock has been released. # C: O(processes + DCs)
pub(crate) fn set_paint_region_for_current(dc: u64, region: ipc::win32_window::PaintRegion) -> Result<(), u64> {
    let dc = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let mut entries = GDI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
    entry.state.set_paint_region(dc, region).map_err(|_| STATUS_INVALID_HANDLE)
}

/// Paint admission supplies an owned update rectangle, never a borrowed user buffer. # C: O(processes + DCs)
pub(crate) fn set_paint_clip_for_current(dc: u64, rect: Rect) -> Result<(), u64> {
    let dc = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let mut entries = GDI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
    entry.state.set_paint_clip(dc, rect).map_err(|error| match error {
        ipc::win32_gdi::GdiError::NoSuchObject => STATUS_INVALID_HANDLE,
        _ => STATUS_INVALID_PARAMETER,
    })
}

/// Return region complexity, never an NTSTATUS disguised as a region value. # C: O(processes + DCs)
pub(crate) fn intersect_clip_rect_for_current(dc: u64, rect: Rect) -> u64 {
    let Ok(dc) = u32::try_from(dc) else { return CLIP_ERROR as u64; };
    let Ok(_gate) = lifecycle::ClientGate::acquire_current() else { return CLIP_ERROR as u64; };
    let Some(current) = sched::live::current() else { return CLIP_ERROR as u64; };
    let mut entries = GDI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))) else { return CLIP_ERROR as u64; };
    entry.state.intersect_clip_rect(dc, rect).unwrap_or(CLIP_ERROR) as u64
}

/// Effective-clip snapshot for kernel callers. # C: O(processes + DCs)
pub(crate) fn app_clip_box_snapshot_for_current(dc: u64) -> Result<(u32, Rect), u64> {
    let dc = u32::try_from(dc).map_err(|_| CLIP_ERROR as u64)?;
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| CLIP_ERROR as u64)?;
    let current = sched::live::current().ok_or(CLIP_ERROR as u64)?;
    let entries = GDI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(CLIP_ERROR as u64)?;
    entry.state.get_app_clip_box(dc).map(|(kind, rect)| (kind as u32, rect)).map_err(|_| CLIP_ERROR as u64)
}

/// Initialize the complete signed RECT from one effective-clip snapshot. # C: O(processes + DCs)
pub(crate) fn get_app_clip_box_for_current(dc: u64, output: u64) -> u64 {
    let Ok((kind, rect)) = app_clip_box_snapshot_for_current(dc) else { return CLIP_ERROR as u64; };
    if output == 0 { return CLIP_ERROR as u64; }
    let mut bytes = [0u8; 16];
    for (index, value) in [rect.left, rect.top, rect.right, rect.bottom].into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    if uaccess::copy_to_user(output, &bytes).is_err() { return CLIP_ERROR as u64; }
    kind as u64
}
