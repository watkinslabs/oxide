//! Persist creation styles and top-level ownership before compositor publication.
use super::*;

/// Snapshot callback identity without retaining GUI locks across user dispatch.
/// # C: O(processes + windows); # Sleeps: no
pub(crate) fn window_call_context_current(hwnd: u64) -> Option<(ipc::win32_window::WindowRecord, bool)> {
    let current = sched::live::current().filter(|task| task.is_nt_personality())?;
    let window = valid_window(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))?;
    let record = entry.state.get(window)?;
    Some((record, record.owner_tid == current.tid as u64))
}

pub(crate) fn set_creation_metadata_current(hwnd: u64, style: u32, ex_style: u32, owner: u64, instance: u64) -> Result<(), ()> {
    let current = sched::live::current().ok_or(())?;
    let window = valid_window(hwnd).ok_or(())?;
    let owner = if owner == 0 { None } else { Some(valid_window(owner).ok_or(())?) };
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(())?;
    entry.state.set_window_styles(window, style, ex_style).map_err(|_| ())?;
    entry.state.set_window_long(window, ipc::win32_window::GWLP_HINSTANCE, 8, instance).map_err(|_| ())?;
    if owner.is_some() { entry.state.set_popup_owner(window, owner).map_err(|_| ())?; }
    Ok(())
}
