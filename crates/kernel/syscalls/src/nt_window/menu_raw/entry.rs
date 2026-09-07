//! The one per-process GUI record every menu ordinal works against.
use crate::nt_window::{GUI, GuiEntry, new_entry};
use alloc::sync::Arc;

/// Resolve, creating on first use, the calling process's GUI record.
/// # C: O(N_process_gui_states)
pub(crate) fn with_entry<R>(f: impl FnOnce(&mut GuiEntry) -> R) -> Option<R> {
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index]))
}

/// The calling thread's id, absent outside an NT thread. # C: O(1)
pub(crate) fn current_tid() -> Option<u64> { sched::live::current().filter(|cur| cur.is_nt_personality()).map(|cur| cur.tid as u64) }
