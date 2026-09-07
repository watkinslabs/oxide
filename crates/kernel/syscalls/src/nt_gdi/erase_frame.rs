//! Erase-only callbacks retain pixels without consuming pending BeginPaint damage.
use super::*;
use ipc::win32_gdi::PaintBacking;
use ipc::win32_window::PaintRegion;

/// Revalidate geometry before merging an auxiliary callback surface. The merge
/// records the coverage as pending output and the pump flushes it; an erase
/// does not transact with the desktop on its own.
/// # C: O(processes + DCs + damage pixels)
pub(crate) fn retain_erase_for_current(hwnd: u32, dc: u32, region: &PaintRegion, layout: PaintBacking) -> Result<(), u64> {
    if crate::nt_window::paint::backing_for_current(hwnd) != Some(layout) { return Err(STATUS_INVALID_HANDLE); }
    let current = sched::live::current().filter(|current| current.is_nt_personality()).ok_or(STATUS_INVALID_HANDLE)?;
    {
        let mut entries = GDI.lock();
        let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
        paint_frame::merge_region(&mut entry.state, hwnd, dc, region, layout).map_err(|_| STATUS_INVALID_PARAMETER)?;
    }
    output::flush_pending_for_current(false);
    Ok(())
}
