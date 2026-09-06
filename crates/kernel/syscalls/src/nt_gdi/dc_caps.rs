//! Device-context handle validity for the capability table.
use super::*;

/// The reference resolves the device context before asking its driver and
/// answers zero when it cannot. # C: O(N_process_gdi_states + N_objects)
pub(crate) fn contains_dc_for_current(dc: u32) -> bool {
    let Some(cur) = sched::live::current() else { return false; };
    if !cur.is_nt_personality() { return false; }
    let entries = GDI.lock();
    entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
        .is_some_and(|entry| entry.state.validate_dc(dc).is_ok())
}
