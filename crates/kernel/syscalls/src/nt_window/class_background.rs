//! Per-process class and DPI state: class background brush recorded at
//! registration and read by the default erase; the process DPI context.
use super::*;

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

/// WNDCLASSEXW-shaped description of one registered class atom, for the
/// class-information query. # C: O(processes + classes)
pub(crate) fn class_description_by_atom_for_current(atom: u16) -> Option<ipc::win32_window::ClassDescription> {
    with_entry(|entry| entry.state.class_description_by_atom(atom)).flatten()
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

/// Retain the caller's 16-bit thunk-lock callback. # C: O(processes)
pub(crate) fn set_thunk_lock_for_current(callback: u64) { with_entry(|entry| entry.thunk_lock = callback); }

/// The awareness context in force for the calling thread: its own override if
/// it set one, otherwise the process context marked as the process's.
/// # C: O(processes + threads)
pub(crate) fn thread_dpi_context_for_current() -> u32 {
    let Some(cur) = sched::live::current() else { return crate::nt_wine_window::dpi_context::UNAWARE; };
    let tid = cur.tid as u64;
    with_entry(|entry| {
        match entry.thread_dpi.iter().find(|(thread, _)| *thread == tid).map(|(_, ctx)| *ctx).filter(|ctx| *ctx != 0) {
            Some(ctx) => ctx,
            None => crate::nt_wine_window::dpi_context::get(entry.dpi_context, crate::nt_wine_window::dpi_context::CURRENT_PROCESS)
                | crate::nt_wine_window::dpi_context::FLAG_PROCESS,
        }
    }).unwrap_or(crate::nt_wine_window::dpi_context::UNAWARE)
}

/// Install the calling thread's awareness context, answering the one it
/// replaced. An invalid context changes nothing and answers zero; a context
/// carrying the process flag clears the thread override rather than storing
/// one, so the thread falls back to the process context.
/// # C: O(processes + threads)
pub(crate) fn set_thread_dpi_context_for_current(ctx: u32) -> u32 {
    let system_dpi = drm::primary_system_dpi();
    if !crate::nt_wine_window::dpi_context::is_valid(ctx, system_dpi) { return 0; }
    let previous = thread_dpi_context_for_current();
    let Some(cur) = sched::live::current() else { return 0; };
    let tid = cur.tid as u64;
    let stored = if ctx & crate::nt_wine_window::dpi_context::FLAG_PROCESS != 0 { 0 } else { ctx };
    with_entry(|entry| {
        match entry.thread_dpi.iter_mut().find(|(thread, _)| *thread == tid) {
            Some(slot) => slot.1 = stored,
            None => if entry.thread_dpi.try_reserve(1).is_ok() { entry.thread_dpi.push((tid, stored)); },
        }
    });
    previous
}
