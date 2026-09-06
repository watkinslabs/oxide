//! Snapshot the current process's canonical DC clip before input usercopy.
use super::*;
use ipc::win32_window::PaintRegion;

/// Fallible owned snapshot; no DC creation, projection or usercopy under GDI lock. # C: O(processes + DCs + paint rectangles)
pub(crate) fn visibility_clip_for_current(dc: u64) -> Option<PaintRegion> {
    let dc = u32::try_from(dc).ok()?;
    let _gate = lifecycle::ClientGate::acquire_current().ok()?;
    let current = sched::live::current()?;
    let entries = GDI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))?;
    entry.state.visibility_region(dc).ok()
}
