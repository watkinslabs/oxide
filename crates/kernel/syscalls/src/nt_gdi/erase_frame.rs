//! Erase-only callbacks retain pixels without consuming pending BeginPaint damage.
use super::*;
use ipc::win32_gdi::PaintBacking;
use ipc::win32_window::PaintRegion;
const STATUS_PENDING_OUTPUT: u64 = 0x103;

/// Revalidate geometry before merging an auxiliary callback surface. # C: O(processes + DCs + pixels)
pub(crate) fn retain_erase_for_current(hwnd: u32, dc: u32, region: &PaintRegion, layout: PaintBacking) -> Result<(), u64> {
    if crate::nt_window::paint::backing_for_current(hwnd) != Some(layout) { return Err(STATUS_INVALID_HANDLE); }
    let current = sched::live::current().filter(|current| current.is_nt_personality()).ok_or(STATUS_INVALID_HANDLE)?;
    let frame = {
        let mut entries = GDI.lock();
        let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
        let frame = paint_frame::capture_region(&mut entry.state, hwnd, dc, region, layout).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let backing = entry.state.window_dc(hwnd).ok_or(STATUS_INVALID_HANDLE)?;
        output::reserve_captured(&mut entry.state, hwnd, backing, frame).map_err(|_| STATUS_INVALID_PARAMETER)
    };
    match output::submit_prepared_for_current(frame) {
        STATUS_SUCCESS | STATUS_PENDING_OUTPUT => Ok(()),
        status => Err(status),
    }
}
