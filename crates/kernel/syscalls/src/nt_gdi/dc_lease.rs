//! GetDCEx publication follows canonical GUI visibility and GDI lease ownership.
use super::*;
use ipc::win32_gdi::DcLeaseRequest;
#[path = "dc_lease/projection.rs"]
mod projection;

/// HWND destruction also removes aliases into another window's surviving backing.
/// Caller validates canonical HWND teardown; all projection deletion follows GDI unlock.
/// # C: O(processes + DCs + selected objects)
pub(crate) fn revoke_window_leases_for_current(hwnd: u32) -> Result<(), u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().filter(|current| current.is_nt_personality()).ok_or(STATUS_INVALID_HANDLE)?;
    let group = Arc::downgrade(&current.thread_group);
    let (binding, removed) = {
        let mut entries = GDI.lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&group)) else { return Ok(()); };
        let before = entry.state.live_handles(); entry.state.revoke_window_leases(hwnd);
        let removed: Vec<_> = before.into_iter().filter(|id| !entry.state.contains_object(*id)).collect();
        (entry.client, removed)
    };
    let mut result = Ok(());
    if let Some(binding) = binding { for handle in removed {
        if binding.delete_handle(handle).is_err() { result = Err(STATUS_INVALID_PARAMETER); }
    } }
    result
}

/// NULL on any failure; GUI snapshot precedes lifecycle/GDI locks. # C: O(processes + objects + regions)
pub(crate) fn get_dc_ex_for_current(hwnd: u32, region: u32, flags: u32) -> u64 {
    let Some(context) = crate::nt_window::dc_lease_context_for_current(hwnd, flags) else { return 0; };
    let Ok(backing) = lifecycle::acquire_window_dc_for_current(context.backing_hwnd, context.backing_width, context.backing_height) else { return 0; };
    let Ok(_gate) = lifecycle::ClientGate::acquire_current() else { return 0; };
    let Some(current) = sched::live::current().filter(|current| current.is_nt_personality()) else { return 0; };
    let Ok(pid) = client::current_process_id() else { return 0; };
    let group = Arc::downgrade(&current.thread_group);
    let prepared = {
        let mut entries = GDI.lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&group)) else { return 0; };
        let before = entry.state.live_handles();
        let request = DcLeaseRequest { hwnd, backing_hwnd: context.backing_hwnd, backing, origin: context.origin,
            screen_origin: context.screen_origin, width: context.logical_width, height: context.logical_height,
            flags: context.flags, owner: context.owner, visible: context.visible, clip_handle: region };
        let Ok(dc) = entry.state.acquire_dc_lease(request) else { return 0; };
        let Ok(state) = entry.state.text_state(dc) else { return 0; };
        let reused = before.contains(&dc);
        let removed: Vec<_> = before.into_iter().filter(|id| !entry.state.contains_object(*id)).collect();
        (dc, state, entry.client, removed, reused)
    };
    let (dc, state, binding, removed, reused) = prepared;
    if let Some(binding) = binding {
        let published = removed.into_iter().all(|id| binding.delete_handle(id).is_ok())
            && projection::acquire(&binding, dc, pid, state, reused).is_ok();
        if !published {
            let removed = {
                let mut entries = GDI.lock();
                if let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&group)) {
                    let before = entry.state.live_handles();
                    let _ = entry.state.revoke_dc_lease(dc);
                    before.into_iter().filter(|id| !entry.state.contains_object(*id)).collect::<Vec<_>>()
                } else { Vec::new() }
            };
            for handle in removed { let _ = binding.delete_handle(handle); }
            let _ = binding.delete_handle(dc);
            return 0;
        }
    }
    u64::from(dc)
}

/// Release the HDC lease, preserving backing identity and pixel storage. # C: O(processes + objects)
pub(crate) fn release_dc_lease_for_current(dc: u32) -> bool {
    let Ok(_gate) = lifecycle::ClientGate::acquire_current() else { return false; };
    let Some(current) = sched::live::current().filter(|current| current.is_nt_personality()) else { return false; };
    let group = Arc::downgrade(&current.thread_group);
    let (binding, state, removed, reset) = {
        let mut entries = GDI.lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&group)) else { return false; };
        let before = entry.state.live_handles();
        let Ok(reset) = entry.state.dc_lease_resets_on_release(dc) else { return false; };
        let Ok(state) = entry.state.release_dc_lease_state(dc) else { return false; };
        let removed: Vec<_> = before.into_iter().filter(|id| !entry.state.contains_object(*id)).collect();
        (entry.client, state, removed, reset)
    };
    if let Some(binding) = binding {
        let Ok(pid) = client::current_process_id() else { return false; };
        return removed.into_iter().all(|id| binding.delete_handle(id).is_ok()) && projection::release(&binding, dc, pid, state, reset).is_ok();
    }
    true
}
