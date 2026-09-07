//! The one per-process GUI record every menu ordinal works against.
pub(crate) use crate::nt_window::owner::with_entry;

/// The calling thread's id, absent outside an NT thread. # C: O(1)
pub(crate) fn current_tid() -> Option<u64> { sched::live::current().filter(|cur| cur.is_nt_personality()).map(|cur| cur.tid as u64) }
