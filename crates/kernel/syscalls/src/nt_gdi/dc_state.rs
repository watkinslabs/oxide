//! Process-scoped access to the device-context state services.
//!
//! Every entry point takes the client lifetime gate, resolves the calling
//! process's GDI owner and hands the canonical state to one closure. No state
//! decision is taken here: the owner owns them all.
use super::*;
use ipc::win32_gdi::{GdiError, GdiManager};

/// Run one operation against the calling process's GDI object owner.
/// # C: O(processes) plus the operation
pub(crate) fn with_state<R>(operation: impl FnOnce(&mut GdiManager) -> Result<R, GdiError>) -> Result<R, GdiError> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| GdiError::NoSuchObject)?;
    let current = sched::live::current().ok_or(GdiError::NoSuchObject)?;
    let mut entries = GDI.lock();
    let entry = entries.iter_mut()
        .find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))
        .ok_or(GdiError::NoSuchObject)?;
    operation(&mut entry.state)
}

/// Publish a newly created object into the client handle table, rolling the
/// creation back when the table refuses it. # C: O(processes + objects)
pub(crate) fn publish_new(handle: u32, remove: impl Fn(&mut GdiManager) -> Result<(), GdiError>) -> Result<(), GdiError> {
    let current = sched::live::current().ok_or(GdiError::NoSuchObject)?;
    let group = Arc::clone(&current.thread_group);
    let binding = { let mut entries = GDI.lock();
        let index = lifecycle::entry_for_current(&mut entries, &group).map_err(|_| GdiError::NoSuchObject)?;
        entries[index].client };
    let Some(binding) = binding else { return Ok(()); };
    let pid = client::current_process_id().map_err(|_| GdiError::NoSuchObject)?;
    lifecycle::publish_or_rollback(binding, handle, || binding.publish_handle(handle, pid), || {
        let mut entries = GDI.lock();
        let index = lifecycle::entry_for_current(&mut entries, &group).map_err(|_| GdiError::NoSuchObject)?;
        remove(&mut entries[index].state)
    }).map_err(|_| GdiError::NoSuchObject)
}

/// Retire a handle from the client table after its object owner released it.
/// # C: O(processes)
pub(crate) fn retire(handle: u32) -> Result<(), GdiError> {
    let current = sched::live::current().ok_or(GdiError::NoSuchObject)?;
    let binding = { let mut entries = GDI.lock();
        entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))
            .and_then(|entry| entry.client) };
    match binding { Some(binding) => binding.delete_handle(handle).map_err(|_| GdiError::NoSuchObject), None => Ok(()) }
}

/// The device geometry the mapping modes read, taken from the same capability
/// table the device-capability ordinal answers from. # C: O(monitors)
pub(crate) fn device_geometry() -> ipc::win32_gdi::DeviceGeometry {
    use crate::nt_wine_window::device_caps;
    let device = device_caps::kernel::current_device();
    ipc::win32_gdi::DeviceGeometry {
        res: ipc::win32_gdi::Size { cx: device_caps::caps(device_caps::HORZRES, device),
            cy: device_caps::caps(device_caps::VERTRES, device) },
        size: ipc::win32_gdi::Size { cx: device_caps::caps(device_caps::HORZSIZE, device),
            cy: device_caps::caps(device_caps::VERTSIZE, device) },
    }
}
