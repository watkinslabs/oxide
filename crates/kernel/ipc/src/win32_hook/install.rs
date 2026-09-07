//! Installation admission: the caller-facing ladder and the table-side rules.
use super::*;

/// Scope one admitted request installs into.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HookScope { Global, Thread(u64) }

/// Caller-facing admission for a window hook. A thread-local request refuses
/// the identifiers that only exist system-wide; a system-wide request refuses
/// the journal identifiers outright, ignores the module of a low-level hook
/// and requires one from every other. Answers the module the table stores.
/// # C: O(1)
pub fn admit_window_hook<'a>(id: i32, thread: Option<u64>, instance: u64, proc_address: u64, module: &'a [u16])
    -> Result<&'a [u16], HookError> {
    if proc_address == 0 { return Err(HookError::InvalidFilterProc); }
    if thread.is_some() {
        if hook_name_is_global_only(id) { return Err(HookError::GlobalOnlyHook); }
        return Ok(module);
    }
    if id == WH_JOURNALRECORD || id == WH_JOURNALPLAYBACK { return Err(HookError::AccessDenied); }
    if id == WH_KEYBOARD_LL || id == WH_MOUSE_LL { return Ok(&[]); }
    if instance == 0 { return Err(HookError::HookNeedsModule); }
    Ok(module)
}

/// Caller-facing admission for a WinEvent hook. An in-context hook needs a
/// module; the event range may not be inverted; a thread-local hook drops the
/// module the same way a low-level window hook does. # C: O(1)
pub fn admit_win_event_hook<'a>(event_min: u32, event_max: u32, instance: u64, thread: Option<u64>, flags: u32,
    module: &'a [u16]) -> Result<&'a [u16], HookError> {
    if flags & WINEVENT_INCONTEXT != 0 && instance == 0 { return Err(HookError::HookNeedsModule); }
    if event_min > event_max { return Err(HookError::InvalidHookFilter); }
    if thread.is_some() { return Ok(&[]); }
    Ok(module)
}

/// Table-side admission, applied after the caller-facing ladder: the
/// identifier must name a chain, a low-level hook is always global and never
/// thread-bound, a global hook that runs in context needs a module, and a
/// thread-local hook may omit its module only inside the installing process.
/// # C: O(1)
pub fn admit_table_install(request: &HookRequest<'_>, caller_process: u64, target_process: Option<u64>)
    -> Result<HookScope, HookError> {
    if request.proc_address == 0 { return Err(HookError::InvalidParameter); }
    if chain_index(request.id).is_none() { return Err(HookError::InvalidParameter); }
    if request.id == WH_KEYBOARD_LL || request.id == WH_MOUSE_LL {
        if request.thread.is_some() { return Err(HookError::InvalidParameter); }
        return Ok(HookScope::Global);
    }
    let Some(thread) = request.thread else {
        if request.module.is_empty() && request.flags & WINEVENT_INCONTEXT != 0 {
            return Err(HookError::InvalidParameter);
        }
        return Ok(HookScope::Global);
    };
    if request.module.is_empty() && target_process != Some(caller_process) {
        return Err(HookError::InvalidParameter);
    }
    Ok(HookScope::Thread(thread))
}
