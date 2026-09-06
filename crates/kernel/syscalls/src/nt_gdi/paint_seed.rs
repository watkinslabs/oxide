//! Paint initialization snapshots GUI before taking the canonical GDI owner.
use super::*;

/// Seed before paint admission so clipped/transparent drawing retains client pixels.
/// # C: O(processes + DCs + client pixels); # Sleeps: client lifetime gate
pub(crate) fn seed_paint_for_current(hwnd: u32, dc: u32) -> Result<(), u64> {
    let layout = crate::nt_window::paint::backing_for_current(hwnd).ok_or(STATUS_INVALID_HANDLE)?;
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().filter(|current| current.is_nt_personality()).ok_or(STATUS_INVALID_HANDLE)?;
    let mut entries = GDI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
    entry.state.seed_paint(hwnd, dc, layout).map_err(|error| match error {
        ipc::win32_gdi::GdiError::NoSuchObject => STATUS_INVALID_HANDLE,
        _ => STATUS_INVALID_PARAMETER,
    })
}
