//! Process binding for canonical brush work; never performs display I/O under GDI.
use super::*;
use ipc::win32_gdi::{GdiError, GdiManager};
#[path = "brush/shared.rs"]
mod shared;
#[path = "brush/publication.rs"]
mod publication;

fn with_owner<R>(action: impl FnOnce(&mut GdiManager) -> Result<R, GdiError>) -> Result<R, u64> {
    let cur = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    if !cur.is_nt_personality() { return Err(STATUS_INVALID_HANDLE); }
    let group = Arc::downgrade(&cur.thread_group);
    let mut entries = GDI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = match entries.iter().position(|entry| entry.group.ptr_eq(&group)) {
        Some(index) => index,
        None => { entries.push(new_entry(&cur.thread_group)); entries.len() - 1 }
    };
    action(&mut entries[index].state).map_err(|error| match error {
        GdiError::NoSuchObject => STATUS_INVALID_HANDLE, _ => STATUS_INVALID_PARAMETER,
    })
}

/// COLORREF input becomes XRGB at the ABI boundary. # C: O(processes)
pub(crate) fn create_solid_brush_for_current(color: u32) -> Result<u32, u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let cur = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let group = Arc::downgrade(&cur.thread_group);
    let (handle, binding) = {
        let mut entries = GDI.lock();
        let index = match entries.iter().position(|entry| entry.group.ptr_eq(&group)) {
            Some(index) => index,
            None => { entries.push(new_entry(&cur.thread_group)); entries.len() - 1 }
        };
        let entry = &mut entries[index];
        let handle = entry.state.create_solid_brush(colorref_xrgb(color)).map_err(|_| STATUS_INVALID_PARAMETER)?;
        (handle, entry.client)
    };
    publication::publish_created(handle, |handle| {
        if let Some(binding) = binding {
            let pid = client::current_process_id().map_err(|_| STATUS_INVALID_HANDLE)?;
            binding.publish_handle(handle, pid).map_err(|_| STATUS_INVALID_PARAMETER)?;
        }
        Ok(())
    }, |handle| {
        with_owner(|state| state.delete_brush(handle))?;
        if let Some(binding) = binding { binding.delete_handle(handle).map_err(|_| STATUS_INVALID_PARAMETER)?; }
        Ok(())
    })
}

/// Resolve both typed identities against the current process owner. # C: O(processes + DCs + brushes)
pub(crate) fn select_brush_for_current(dc: u64, brush: u64) -> Result<u32, u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let (_, binding) = text::snapshot_binding(dc)?;
    let dc = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    let brush = u32::try_from(brush).map_err(|_| STATUS_INVALID_HANDLE)?;
    let (previous, live) = with_owner(|state| {
        let previous = state.select_brush(dc, brush)?;
        Ok((previous, state.contains_object(previous)))
    })?;
    publication::finish_selection(previous, live, |handle| {
        if let Some(binding) = binding { binding.delete_handle(handle).map_err(|_| STATUS_INVALID_PARAMETER)?; }
        Ok(())
    })
}

/// Paint canonical backing; presentation remains the existing EndPaint owner. # C: O(processes + DCs + brushes + pixels)
pub(crate) fn pat_blt_for_current(dc: u64, x: i32, y: i32, width: i32, height: i32, rop: u32) -> Result<(), u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let (_, binding) = text::snapshot_binding(dc)?;
    let dc = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    // Usercopy may fault; only copied mapping identity survives the owner lock.
    let colors = match binding {
        Some(binding) => {
            let bytes = binding.read_dc_attr(dc).map_err(|_| STATUS_INVALID_PARAMETER)?;
            Some(shared::colors(&bytes).map_err(|_| STATUS_INVALID_PARAMETER)?)
        }
        None => None,
    };
    with_owner(|state| match colors {
        Some(colors) => state.pat_blt_shared_colors(dc, x, y, width, height, rop, colors),
        None => state.pat_blt(dc, x, y, width, height, rop),
    })
}

/// Set DC_BRUSH color, returning the previous COLORREF. # C: O(processes + DCs)
pub(crate) fn set_dc_brush_color_for_current(dc: u64, color: u32) -> Result<u32, u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let (_, binding) = text::snapshot_binding(dc)?;
    let dc = u32::try_from(dc).map_err(|_| STATUS_INVALID_HANDLE)?;
    if let Some(binding) = binding {
        let bytes = binding.read_dc_attr(dc).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let (old, encoded) = shared::replacement(&bytes, color).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let address = binding.dc_attr_address(dc).map_err(|_| STATUS_INVALID_PARAMETER)?
            .checked_add(syscall::nt_gdi_client::dc::BRUSH_COLOR as u64).ok_or(STATUS_INVALID_PARAMETER)?;
        uaccess::copy_to_user(address, &encoded).map_err(|_| STATUS_INVALID_PARAMETER)?;
        return Ok(old);
    }
    with_owner(|state| state.set_dc_brush_color(dc, colorref_xrgb(color))).map(colorref_xrgb)
}

fn colorref_xrgb(color: u32) -> u32 { ((color & 0xff) << 16) | (color & 0xff00) | ((color >> 16) & 0xff) }
