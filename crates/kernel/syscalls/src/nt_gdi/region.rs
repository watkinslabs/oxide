//! HRGN adapters reuse the existing canonical GDI/client lifetime transaction.
use super::*;
use ipc::win32_window::PaintRegion;
use ipc::win32_gdi::Rect;
const RGN_COPY:i32=5;

/// Replace existing HRGN geometry without allocating or republishing identity. # C: O(processes + regions)
pub(crate) fn set_rect_region_for_current(handle:u64,rect:Rect)->bool{
    let Ok(handle)=u32::try_from(handle)else{return false;};
    let Ok(_gate)=lifecycle::ClientGate::acquire_current()else{return false;};
    let Some(current)=sched::live::current()else{return false;};
    let mut entries=GDI.lock();
    let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&current.thread_group)))else{return false;};
    entry.state.set_rect_region(handle,rect).is_ok()
}

/// Publish the exact owned region or roll back both canonical and client identity. # C: O(processes + regions)
pub(crate) fn create_region_for_current(region: PaintRegion) -> Result<u32,u64> {
    create(|state| state.create_region(region))
}

/// Raw rectangular creation uses the same canonical normalization and transaction. # C: O(processes + regions)
pub(crate) fn create_rect_region_for_current(rect: Rect) -> Result<u32,u64> {
    create(|state| state.create_rect_region(rect))
}

fn create(operation: impl FnOnce(&mut ipc::win32_gdi::GdiManager) -> Result<u32,ipc::win32_gdi::GdiError>) -> Result<u32,u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let group = Arc::clone(&current.thread_group);
    let bound = {
        let mut entries = GDI.lock();
        let index = lifecycle::entry_for_current(&mut entries,&group).map_err(|_| STATUS_INVALID_HANDLE)?;
        entries[index].client.is_some()
    };
    let pid = bound.then(client::current_process_id).transpose().map_err(|_| STATUS_INVALID_PARAMETER)?;
    let (binding,handle) = {
        let mut entries = GDI.lock();
        let index = lifecycle::entry_for_current(&mut entries,&group).map_err(|_| STATUS_INVALID_HANDLE)?;
        let handle = operation(&mut entries[index].state).map_err(|_| STATUS_INVALID_PARAMETER)?;
        (entries[index].client,handle)
    };
    if let (Some(binding),Some(pid)) = (binding,pid) {
        lifecycle::publish_or_rollback(binding,handle, || binding.publish_handle(handle,pid), || {
            let mut entries = GDI.lock();
            let index = lifecycle::entry_for_current(&mut entries,&group).map_err(|_| ipc::win32_gdi::GdiError::NoSuchObject)?;
            entries[index].state.delete_region(handle)
        }).map_err(|_| STATUS_INVALID_PARAMETER)?;
    }
    Ok(handle)
}

/// Boolean region operations mutate only the canonical destination under the lifetime gate. # C: exact region-operation cost
pub(crate) fn combine_region_for_current(destination:u64, source1:u64, source2:u64, mode:i32) -> u32 {
    let (Ok(destination),Ok(source1)) = (u32::try_from(destination),u32::try_from(source1)) else { return 0; };
    let source2 = if mode == RGN_COPY { 0 } else { let Ok(value)=u32::try_from(source2) else { return 0; }; value };
    let Ok(_gate)=lifecycle::ClientGate::acquire_current() else { return 0; };
    let Some(current)=sched::live::current() else { return 0; };
    let mut entries=GDI.lock();
    let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&current.thread_group))) else { return 0; };
    entry.state.combine_region(destination,source1,source2,mode).unwrap_or(0)
}

/// Return an owned exact snapshot before any caller copyout or callback. # C: O(processes + regions + rectangles)
pub(crate) fn region_snapshot_for_current(handle: u64) -> Result<PaintRegion,u64> {
    let handle = u32::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let entries = GDI.lock();
    let entry = entries.iter().find(|e| e.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
    entry.state.region_snapshot(handle).map_err(|_| STATUS_INVALID_HANDLE)
}

/// Preserve handle identity while replacing admitted exact geometry. # C: O(processes + regions)
pub(crate) fn replace_region_for_current(handle: u64, region: PaintRegion) -> Result<(),u64> {
    let handle = u32::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let mut entries = GDI.lock();
    let entry = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
    entry.state.replace_region(handle,region).map_err(|_| STATUS_INVALID_HANDLE)
}

/// Read initialized bounds and complexity from the canonical region identity. # C: O(processes + regions + rectangles)
pub(crate) fn region_box_for_current(handle: u64) -> Result<(u32,Rect),u64> {
    let handle = u32::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let entries = GDI.lock();
    let entry = entries.iter().find(|e| e.group.ptr_eq(&Arc::downgrade(&current.thread_group))).ok_or(STATUS_INVALID_HANDLE)?;
    entry.state.region_box(handle).map_err(|_| STATUS_INVALID_HANDLE)
}

/// Generic lifecycle deletion clears the projected entry and canonical region together. # C: O(processes + objects)
pub(crate) fn delete_region_for_current(handle: u64) -> Result<(),u64> {
    let handle = u32::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
    // Type-check before generic deletion so non-region handles never become accidental targets.
    let _ = region_snapshot_for_current(handle as u64)?;
    lifecycle::delete_object_for_current(handle).map_err(|_| STATUS_INVALID_HANDLE)
}
