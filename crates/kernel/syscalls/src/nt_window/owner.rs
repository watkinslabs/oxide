//! Process GUI entry construction; every adapter uses the same initial state.
use super::*;

pub(super) fn new_entry(group: &Arc<sched::thread_group::ThreadGroup>) -> GuiEntry {
    GuiEntry { group: Arc::downgrade(group), state: ipc::win32_window::WindowManager::new(),
        menus: ipc::win32_menu::MenuManager::new(), accelerators: ipc::win32_accel::AcceleratorTables::new(), dpi_context: 0, wait: Arc::new(sched::live::WaitList::new()),
        foreground: false, next_create: 1, pending_creates: Vec::new(), pending_positions: Vec::new(), remote_positions: Vec::new(), retrievals: Vec::new(), sent: send::Queue::new(), redraw: redraw::Queue::new(), scroll_pending: scroll::pending::Queue::default(), paint_callbacks: paint_callbacks::Queue::new(), client_procs_w: 0, builtins_registered: false, init_callback_issued: false, contexts: ipc::win32_imc::InputContexts::new(), defer: ipc::win32_window::DeferBatches::new(), startup_info_flags: 0, process_layout: 0, menu_tracking: None }

}

/// Run one closure against the calling NT process's mutable GUI state,
/// creating the entry on first use. # C: O(N_nt_processes)
pub(super) fn with_state_mut<T>(f: impl FnOnce(&mut ipc::win32_window::WindowManager) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index].state))
}

/// Run one closure against the calling NT process's GUI state. # C: O(N_nt_processes)
pub(super) fn with_state<T>(f: impl FnOnce(&ipc::win32_window::WindowManager) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    Some(f(&entry.state))
}

/// Calling thread id, as the window manager keys its queues. # C: O(1)
pub(super) fn current_tid() -> Option<u64> {
    sched::live::current().filter(|task| task.is_nt_personality()).map(|task| task.tid as u64)
}

/// Run one closure against the calling NT process's GUI state and wake every
/// thread parked on its queue, as any state change that queues a message must.
/// # C: O(N_nt_processes + N_waiters)
pub(super) fn with_state_waking<T>(f: impl FnOnce(&mut ipc::win32_window::WindowManager) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let (value, wait) = {
        let mut entries = GUI.lock();
        entries.retain(|entry| entry.group.upgrade().is_some());
        let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
            .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
        (f(&mut entries[index].state), Arc::clone(&entries[index].wait))
    };
    wait.wake_all();
    Some(value)
}
