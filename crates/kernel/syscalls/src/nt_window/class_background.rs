//! Per-process class and DPI state: class background brush recorded at
//! registration and read by the default erase; the process DPI context.
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

/// Admit a whole WNDCLASSEXW, cursor included, into the canonical class owner.
/// # C: O(processes + classes)
pub(crate) fn register_class_desc_for_current(desc: ipc::win32_window::ClassRegistration<'_>) -> Option<u64> {
    with_entry(|entry| entry.state.register_class_desc(desc).ok().map(|atom| atom as u64)).flatten()
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

fn with_entry<T>(f: impl FnOnce(&mut GuiEntry) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index]))
}

/// Stored process DPI context; zero when never set. # C: O(processes)
pub(crate) fn dpi_context_for_current() -> Option<u32> { with_entry(|entry| entry.dpi_context) }

/// # C: O(processes)
pub(crate) fn set_dpi_context_for_current(ctx: u32, system_dpi: u32) -> Result<(), u32> {
    with_entry(|entry| crate::nt_wine_window::dpi_context::set(&mut entry.dpi_context, ctx, system_dpi))
        .unwrap_or(Err(crate::nt_wine_window::dpi_context::ERROR_INVALID_PARAMETER))
}
