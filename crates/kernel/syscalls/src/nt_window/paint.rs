//! Paint admission releases GUI ownership before faultable copyout (`31fj`).
use super::*;

/// Copy canonical geometry before taking the GDI owner. # C: O(processes + windows)
pub(crate) fn backing_for_current(hwnd: u32) -> Option<ipc::win32_gdi::PaintBacking> {
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let window = ipc::win32_window::WindowId::from_raw(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    layout(&entry.state, window)
}

fn layout(state: &ipc::win32_window::WindowManager, window: ipc::win32_window::WindowId) -> Option<ipc::win32_gdi::PaintBacking> {
    let bounds = state.rect(window)?;
    let client = state.get(window)?.client_rect.unwrap_or(bounds);
    Some(ipc::win32_gdi::PaintBacking { width: bounds.right.checked_sub(bounds.left)?, height: bounds.bottom.checked_sub(bounds.top)?,
        client: ipc::win32_gdi::Rect { left: client.left.checked_sub(bounds.left)?, top: client.top.checked_sub(bounds.top)?,
            right: client.right.checked_sub(bounds.left)?, bottom: client.bottom.checked_sub(bounds.top)? } })
}

pub(crate) fn current_rect(hwnd: u64) -> Option<ipc::win32_window::WindowRect> {
    let window = valid_window(hwnd)?;
    let cur = sched::live::current()?;
    let entries = GUI.lock();
    entries.iter().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &cur.thread_group)))?.state.paint_rect(window).ok()
}

/// Snapshot damage and layout under one GUI ownership interval. # C: O(processes + windows + region)
pub(crate) fn presentation_for_current(hwnd: u32) -> Option<(ipc::win32_gdi::PaintBacking, ipc::win32_window::PaintRegion)> {
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let window = ipc::win32_window::WindowId::from_raw(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    Some((layout(&entry.state, window)?, entry.state.paint_region(window).ok()?))
}

/// Exact session coverage, copied before entering the GDI owner. # C: O(processes + windows + region)
pub(crate) fn current_region(hwnd: u64) -> Option<ipc::win32_window::PaintRegion> {
    let window = valid_window(hwnd)?;
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let entries = GUI.lock();
    entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?.state.paint_region(window).ok()
}

/// Raw paint reserves before callbacks; PAINTSTRUCT copyout belongs to terminal preparation.
/// # C: O(processes + windows + region); # Sleeps: no
pub(crate) fn reserve_for_current(hwnd: u64) -> Result<ipc::win32_window::WindowRect, u64> {
    let window = valid_window(hwnd).ok_or(STATUS_INVALID_HANDLE)?;
    let cur = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let group = Arc::downgrade(&cur.thread_group);
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&group)).ok_or(STATUS_INVALID_HANDLE)?;
    entry.state.begin_paint_rect(window).map_err(|_| STATUS_INVALID_HANDLE)
}

pub(super) fn begin(hwnd: u64, destination: syscall::UserPtr<syscall::nt::NtWindowRect>) -> u64 {
    let region = match reserve_for_current(hwnd) { Ok(region) => region, Err(status) => return status };
    let result = copy_rect(destination, region);
    if result != STATUS_SUCCESS {
        let Some(window) = valid_window(hwnd) else { return STATUS_INVALID_HANDLE; };
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_HANDLE; };
        let group = Arc::downgrade(&cur.thread_group);
        let mut entries = GUI.lock();
        if let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&group)) {
            let _ = entry.state.end_paint(window);
        }
    }
    result
}
