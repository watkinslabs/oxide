//! One-window fact snapshots for the raw `NtUserCallHwnd` multiplexer.
use super::*;
use crate::nt_wine_window::hwnd_call::Snapshot;

/// None for a handle the calling process does not own. # C: O(processes + windows * depth)
pub(crate) fn hwnd_snapshot_for_current(hwnd: u64) -> Option<Snapshot> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let id = valid_window(hwnd)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let state = &entry.state;
    let record = state.get(id)?;
    let mut ancestors_visible = true;
    let mut parent = record.parent;
    let mut depth = 0;
    while let Some(up) = parent {
        let Some(above) = state.get(up) else { break; };
        if above.style & ipc::win32_window::WS_VISIBLE == 0 { ancestors_visible = false; break; }
        parent = above.parent;
        depth += 1;
        if depth > 64 { break; }
    }
    Some(Snapshot {
        hwnd: id.raw(),
        parent: record.parent.map(|p| p.raw()).unwrap_or(0),
        owner: record.owner.map(|o| o.raw()).unwrap_or(0),
        style: record.style,
        unicode: record.unicode,
        ancestors_visible,
        current_thread: record.owner_tid == cur.tid as u64,
        text_length: state.text(id).map(|t| t.len() as u32).unwrap_or(0),
        dpi: drm::primary_system_dpi(),
    })
}
