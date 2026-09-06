//! Revoke canonical HWNDs before cancelling sends, while the exiting Task still owns its mm.
use super::*;

/// # C: O(windows³ + pending requests); # Sleeps: yes; no GUI lock across usercopy/transport.
pub(crate) fn cleanup_thread_at_exit(task: &sched::Task) {
    paint_callbacks::cancel_current_thread();
    let group = &task.thread_group;
    let (removed, atoms, paint_dcs) = {
        let mut entries = GUI.lock();
        let Some(entry) = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(group))) else { return; };
        let (removed, atoms, mut paint_dcs) = entry.state.exit_thread_with_resources(task.tid as u64);
        for window in &removed { entry.paint_callbacks.cancel_window(window.raw() as u64); }
        paint_dcs.retain(|dc| !entry.paint_callbacks.holds_dc(*dc));
        entry.redraw.cancel_thread(task.tid as u64);
        entry.scroll_pending.cancel_tid(task.tid as u64);
        for window in &removed { entry.redraw.cancel_window(*window); }
        for window in &removed { entry.scroll_pending.cancel_root(window.raw() as u64); }
        entry.pending_creates.retain(|pending| !removed.iter().any(|id| id.raw() as u64 == pending.hwnd));
        crate::nt_retrieval_policy::cancel_thread(&mut entry.retrievals, task.tid as u64);
        (removed, atoms, paint_dcs)
    };
    { let mut owner = USER_ATOMS.lock(); for atom in atoms { owner.release_property_atom(atom); } }
    for dc in paint_dcs { let _ = crate::nt_gdi::delete_paint_dc_current(dc); }
    // Revocation above prevents a concurrent sender from admitting new work for
    // the retiring owner between this cancellation and scheduler retirement.
    position::cancel_position_thread(group, task.tid as u64);
    send::cancel_thread(group, task.tid as u64);
    for window in removed {
        paint_cleanup::window_for_current(window.raw() as u64);
        send::cancel_window(group, window.raw() as u64);
        position::cancel_position_window(group, window.raw() as u64);
        let _ = bridge::publish_destroy_current(window.raw() as u64);
        crate::nt_gdi::destroy_window_dc_for_current(window.raw());
    }
}
