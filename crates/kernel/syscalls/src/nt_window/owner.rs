//! Process GUI entry construction; every adapter uses the same initial state.
use super::*;

pub(super) fn new_entry(group: &Arc<sched::thread_group::ThreadGroup>) -> GuiEntry {
    GuiEntry { group: Arc::downgrade(group), state: ipc::win32_window::WindowManager::new(),
        menus: ipc::win32_menu::MenuManager::new(), accelerators: ipc::win32_accel::AcceleratorTables::new(), dpi_context: 0, wait: Arc::new(sched::live::WaitList::new()),
        foreground: false, next_create: 1, pending_creates: Vec::new(), pending_positions: Vec::new(), remote_positions: Vec::new(), retrievals: Vec::new(), sent: send::Queue::new(), redraw: redraw::Queue::new(), scroll_pending: scroll::pending::Queue::default(), paint_callbacks: paint_callbacks::Queue::new() }
}
