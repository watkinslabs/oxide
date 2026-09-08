//! Process GUI entry construction; every adapter uses the same initial state.
use super::*;

/// The queue wait list IS the process NT-object fanout list, so a thread
/// parked in `MsgWaitForMultipleObjectsEx` is woken by a queue post and by an
/// object another thread signals, from one wait.
#[inline(never)]
pub(super) fn new_entry(group: &Arc<sched::thread_group::ThreadGroup>) -> GuiEntry {
    GuiEntry { group: Arc::downgrade(group), state: ipc::win32_window::WindowManager::new(),
        menus: ipc::win32_menu::MenuManager::new(), accelerators: ipc::win32_accel::AcceleratorTables::new(), dpi_context: 0, wait: group.nt_handles().waiter_list(),
        foreground: false, next_create: 1, pending_creates: Vec::new(), pending_positions: Vec::new(), remote_positions: Vec::new(), retrievals: Vec::new(), sent: send::Queue::new(), redraw: redraw::Queue::new(), scroll_pending: scroll::pending::Queue::default(), paint_callbacks: paint_callbacks::Queue::new(), client_procs_w: 0, builtins_registered: false, init_callback_issued: false, contexts: ipc::win32_imc::InputContexts::new(), defer: ipc::win32_window::DeferBatches::new(), startup_info_flags: 0, process_layout: 0, menu_tracking: None, menu_track: None, idle: false, key_menu: ipc::win32_window::nonclient_menu::KeyMenuLatch::default(), sys_key: super::key_message::SysKeyLatch::default(), hardware: None, last_click: None }

}

/// Index of the calling process's entry, created on first use. Never inlined:
/// it builds a whole `GuiEntry` as a temporary, and inlining that into every
/// caller reserved the entry's full size on the stack of paths that already
/// run close to the guard page.
/// # C: O(N_nt_processes)
#[inline(never)]
pub(in crate::nt_window) fn entry_index(entries: &mut Vec<GuiEntry>, group: &Arc<sched::thread_group::ThreadGroup>) -> usize {
    entries.retain(|entry| entry.group.upgrade().is_some());
    if let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, group))) { return index; }
    entries.push(new_entry(group));
    entries.len() - 1
}

/// Run one closure against the calling NT process's whole GUI record,
/// creating it on first use. State that lives beside the window manager on the
/// record — the input contexts, the send queue — is reached through this.
/// # C: O(N_nt_processes)
pub(in crate::nt_window) fn with_entry<T>(f: impl FnOnce(&mut GuiEntry) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    let index = entry_index(&mut entries, &group);
    Some(f(&mut entries[index]))
}

/// Run one closure against the calling NT process's mutable GUI state,
/// creating the entry on first use. # C: O(N_nt_processes)
pub(super) fn with_state_mut<T>(f: impl FnOnce(&mut ipc::win32_window::WindowManager) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    let index = entry_index(&mut entries, &group);
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
        let index = entry_index(&mut entries, &group);
        (f(&mut entries[index].state), Arc::clone(&entries[index].wait))
    };
    wait.wake_all();
    Some(value)
}
