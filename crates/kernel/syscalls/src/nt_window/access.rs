//! Resolve the calling process's canonical window state. Every decision lives
//! in the window owner; this module only finds it.
use super::*;

/// Locate or create the calling process's window state for a mutation.
/// # C: O(N_processes)
pub(crate) fn with_state_mut<T>(f: impl FnOnce(&mut ipc::win32_window::WindowManager) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index].state))
}

/// Read the calling process's window state; a process with none answers none.
/// # C: O(N_processes)
pub(crate) fn with_state<T>(f: impl FnOnce(&ipc::win32_window::WindowManager) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    Some(f(&entry.state))
}

/// Locate the calling process's deferred-position batches. # C: O(N_processes)
pub(crate) fn with_defer_mut<T>(f: impl FnOnce(&mut ipc::win32_window::DeferBatches) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index].defer))
}

/// Mutate whichever process owns one window; the window tree spans processes.
/// # C: O(N_processes + N_windows)
pub(crate) fn with_window_mut<T>(id: ipc::win32_window::WindowId,
    f: impl FnOnce(&mut ipc::win32_window::WindowManager) -> T) -> Option<T> {
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.state.get(id).is_some())?;
    Some(f(&mut entries[index].state))
}

/// Whether any NT process owns one window. # C: O(N_processes + N_windows)
pub(crate) fn window_exists(id: ipc::win32_window::WindowId) -> bool {
    GUI.lock().iter().any(|entry| entry.state.get(id).is_some())
}
