//! One creation transaction for object kinds whose client projection is a bare
//! handle entry: create under the owner lock, publish, roll back on failure.
use alloc::sync::Arc;
use ipc::win32_gdi::{GdiError, GdiManager};
use super::{ClientGate, LifecycleError, client, entry_for_current, publish_or_rollback};

/// Rollback runs against the same owner the creation used, so a failed
/// publication never leaves a canonical object the client cannot name.
/// # C: O(processes) plus the creation's own cost
pub fn create_object_for_current(create: impl FnOnce(&mut GdiManager) -> Result<u32, GdiError>,
    rollback: impl FnOnce(&mut GdiManager, u32) -> Result<(), GdiError>) -> Result<u32, LifecycleError<GdiError>> {
    let gate = ClientGate::acquire_current().map_err(LifecycleError::Client)?;
    let current = sched::live::current().ok_or(LifecycleError::Client(client::ClientError::NoCurrentProcess))?;
    let group = Arc::clone(&current.thread_group);
    let bound = {
        let mut entries = super::super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        entries[index].client.is_some()
    };
    let pid = bound.then(client::current_process_id).transpose().map_err(LifecycleError::Client)?;
    let (binding, handle) = {
        let mut entries = super::super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        let binding = entries[index].client;
        let handle = create(&mut entries[index].state).map_err(LifecycleError::Canonical)?;
        (binding, handle)
    };
    if let (Some(binding), Some(pid)) = (binding, pid) {
        if let Err(error) = publish_or_rollback(binding, handle, || binding.publish_handle(handle, pid), || {
            let mut entries = super::super::GDI.lock();
            let index = entry_for_current(&mut entries, &group).map_err(|_| GdiError::NoSuchObject)?;
            rollback(&mut entries[index].state, handle)
        }) {
            return Err(error);
        }
    }
    drop(gate);
    Ok(handle)
}
