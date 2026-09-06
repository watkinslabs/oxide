// Current-thread canonical caret queries.

use alloc::sync::Arc;
use super::CaretPos;
use super::super::GUI;

/// Read the current queue caret client position for GetCaretPos.
/// # C: O(GUI entries + queues)
pub(crate) fn position_for_current() -> Option<CaretPos> {
    let current = sched::live::current()?;
    if !current.is_nt_personality() { return None; }
    let group = Arc::clone(&current.thread_group);
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group)))?;
    let (x, y) = entry.state.current_caret_position(current.tid as u64)?;
    Some(CaretPos { x, y })
}
