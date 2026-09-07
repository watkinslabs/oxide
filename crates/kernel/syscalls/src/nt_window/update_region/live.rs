//! Live update-region routing against the canonical window and GDI owners.
use super::super::*;
use super::raw::{decode, Request, ERROR_INVALID_WINDOW_HANDLE};
use alloc::sync::Arc;
use ipc::win32_window::{PaintRegion, RDW_ERASENOW, RDW_NOCHILDREN};

/// Route one update-region ordinal. # C: O(1) plus the arm's own cost
pub(crate) fn route(ordinal: u64, args: [u64; 3]) -> Option<u64> {
    match decode(ordinal, args)? {
        Request::Redraw { hwnd, rect, region, flags } => Some(redraw::for_current(desktop_if_absent(hwnd), rect, region, flags)),
        Request::NoWindow => { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_WINDOW_HANDLE as u64); Some(0) }
        Request::ReadUpdateRect { hwnd, rect, erase } => Some(read_update_rect(hwnd, rect, erase)),
        Request::ReadUpdateRgn { hwnd, region, erase } => Some(read_update_rgn(hwnd, region, erase)),
        Request::ExcludeUpdate { dc, hwnd } => Some(exclude_update(dc, hwnd)),
    }
}

/// A rectangle entry naming no window addresses the whole desktop tree. # C: O(1)
fn desktop_if_absent(hwnd: u64) -> u64 {
    if hwnd != 0 { return hwnd; }
    crate::nt_wine_window::builtin_classes::kernel::get_desktop_window()
}

/// Run the pending nonclient paint and background erase the query owes before
/// it reports coverage, which is what the erase request asks for. # C: O(windows); # Sleeps: yes
fn drive_erase(hwnd: u64, erase: bool) {
    if erase { let _ = redraw::for_current(hwnd, 0, 0, RDW_ERASENOW | RDW_NOCHILDREN); }
}

fn update_region_for_current(hwnd: u64) -> Option<PaintRegion> {
    let window = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw)?;
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    entries[index].state.update_region(window).ok()
}

/// Report the update box in client coordinates, and whether coverage remains.
/// # C: O(windows + region); # Sleeps: yes
fn read_update_rect(hwnd: u64, rect: u64, erase: bool) -> u64 {
    drive_erase(hwnd, erase);
    let Some(region) = update_region_for_current(hwnd) else { return 0; };
    let bounds = region.bounds();
    if rect != 0 {
        let box_rect = bounds.unwrap_or(ipc::win32_window::WindowRect { left: 0, top: 0, right: 0, bottom: 0 });
        let mut bytes = [0u8; 16];
        for (index, value) in [box_rect.left, box_rect.top, box_rect.right, box_rect.bottom].into_iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        if uaccess::copy_to_user(rect, &bytes).is_err() { return 0; }
    }
    bounds.is_some() as u64
}

/// Copy the update coverage into the caller's region and report its complexity.
/// # C: O(windows + region); # Sleeps: yes
fn read_update_rgn(hwnd: u64, target: u64, erase: bool) -> u64 {
    drive_erase(hwnd, erase);
    let Some(region) = update_region_for_current(hwnd) else { return ipc::win32_gdi::CLIP_ERROR as u64; };
    let complexity = ipc::win32_window::region_complexity(&region);
    if crate::nt_gdi::replace_region_for_current(target, region).is_err() { return ipc::win32_gdi::CLIP_ERROR as u64; }
    complexity as u64
}

/// Remove the window's update coverage from the device context's clip.
/// # C: O(windows + DCs + region)
fn exclude_update(dc: u64, hwnd: u64) -> u64 {
    let Some(region) = update_region_for_current(hwnd) else { return ipc::win32_gdi::CLIP_ERROR as u64; };
    crate::nt_gdi::exclude_clip_region_for_current(dc, &region)
}
