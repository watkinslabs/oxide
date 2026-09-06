//! Canonical process GDI owner construction; client stores mapping identity only.
use super::*;

pub(super) fn new_entry(group: &Arc<sched::thread_group::ThreadGroup>) -> GdiEntry {
    GdiEntry { group: Arc::downgrade(group), state: ipc::win32_gdi::GdiManager::new(), client: None, output_pump: output::OutputPump::default() }
}
