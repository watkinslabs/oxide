//! Protected canonical brushes publish through the process client lifetime gate.
use super::*;

/// Session system-colour values. A role keeps its documented default until a
/// set replaces it, and every brush and query reads through this table.
static SYSTEM_COLORS: Spinlock<ipc::win32_gdi::SystemColorTable, GdiLockClass> =
    Spinlock::new(ipc::win32_gdi::SystemColorTable::new());

/// # C: O(1)
pub(crate) fn system_color_value(role: ipc::win32_gdi::SystemColor) -> u32 { SYSTEM_COLORS.lock().value(role) }

/// Store one role's colour and report the value it replaced. # C: O(1)
pub(crate) fn set_system_color(role: ipc::win32_gdi::SystemColor, value: u32) -> u32 {
    SYSTEM_COLORS.lock().set(role, value)
}

/// Cached identity survives application deletion and failed projection. # C: O(processes + brushes)
pub(crate) fn system_color_brush_for_current(role: ipc::win32_gdi::SystemColor) -> Result<u32, u64> {
    let _gate = lifecycle::ClientGate::acquire_current().map_err(|_| STATUS_INVALID_HANDLE)?;
    let current = sched::live::current().ok_or(STATUS_INVALID_HANDLE)?;
    let group = Arc::downgrade(&current.thread_group);
    let pid = client::current_process_id().map_err(|_| STATUS_INVALID_HANDLE)?;
    let value = system_color_value(role);
    let (handle, binding) = {
        let mut entries = GDI.lock();
        let index = match entries.iter().position(|entry| entry.group.ptr_eq(&group)) {
            Some(index) => index,
            None => { entries.push(new_entry(&current.thread_group)); entries.len() - 1 }
        };
        let entry = &mut entries[index];
        (entry.state.system_brush_value(role, value).map_err(|_| STATUS_INVALID_PARAMETER)?, entry.client)
    };
    if let Some(binding) = binding {
        if binding.publish_handle(handle, pid).is_err() {
            binding.delete_handle(handle).map_err(|_| STATUS_INVALID_PARAMETER)?;
            return Err(STATUS_INVALID_PARAMETER);
        }
    }
    Ok(handle)
}
