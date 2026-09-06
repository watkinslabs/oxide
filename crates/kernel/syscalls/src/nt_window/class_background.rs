//! Class background brush: recorded at registration, read by the default erase.
use super::*;

/// # C: O(processes + classes); the raw hbrBackground enters the canonical class owner.
pub(crate) fn register_class_with_background_for_current(name: &[u16], wndproc: u64, extra: i32, unicode: bool, style: u32, background: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    entries[index].state.register_class_with_background(name, wndproc, extra, unicode, style, background).ok().map(|atom| atom as u64)
}

/// Raw class background, class style and client rectangle of a window the
/// calling process owns. # C: O(processes + windows + classes)
pub(crate) fn class_background_for_current(hwnd: u64) -> Option<(u64, u32, Option<ipc::win32_window::WindowRect>)> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let id = valid_window(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    Some((entry.state.class_background(id)?, entry.state.position_class_style(id).unwrap_or(0), entry.state.client_rect(id)))
}
