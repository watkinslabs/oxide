//! Selected object queries read the canonical DC under its existing lifetime gate.
use super::*;

/// # C: O(processes + DCs); # Sleeps: gate; no usercopy under GDI lock
pub(crate) fn selected_object_current(dc: u64, kind: u32) -> u64 {
    let Ok(dc) = u32::try_from(dc) else { return 0; };
    let Ok(_gate) = lifecycle::ClientGate::acquire_current() else { return 0; };
    let Some(current) = sched::live::current() else { return 0; };
    let entries = GDI.lock();
    entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))
        .and_then(|entry| entry.state.selected_object(dc, kind)).map(u64::from).unwrap_or(0)
}
