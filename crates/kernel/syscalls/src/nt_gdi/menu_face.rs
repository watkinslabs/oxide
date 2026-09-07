//! The one face menu text is measured and drawn with, held per process the
//! way the reference holds one menu font object per process.
use super::*;

/// Handle of the nonclient profile's menu font for the calling process,
/// created on first use and reused by every menu paint after it.
/// # C: O(processes + objects)
pub(crate) fn menu_face_for_current() -> Result<u32, u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let group = Arc::downgrade(&current.thread_group);
    let mut entries = GDI.lock();
    let index = match entries.iter().position(|entry| entry.group.ptr_eq(&group)) {
        Some(index) => index,
        None => { entries.push(new_entry(&current.thread_group)); entries.len() - 1 }
    };
    entries[index].state.menu_face().map_err(|_| STATUS_INVALID_PARAMETER)
}
