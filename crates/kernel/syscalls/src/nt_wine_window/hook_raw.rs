//! Hook ordinal decoding. Installation admission and the chain walk live in
//! the hook owner; this module decodes arguments and encodes results.
use ipc::win32_hook::{HookError, WH_WINEVENT};

pub(crate) const CALL_NEXT_HOOK: u64 = 0x133b;
pub(crate) const NOTIFY_WIN_EVENT: u64 = 0x14c1;
pub(crate) const SET_WIN_EVENT_HOOK: u64 = 0x1599;
pub(crate) const SET_WINDOWS_HOOK: u64 = 0x15af;
pub(crate) const UNHOOK_WIN_EVENT: u64 = 0x15da;
pub(crate) const UNHOOK_WINDOWS_HOOK: u64 = 0x15db;
pub(crate) const UNHOOK_WINDOWS_HOOK_EX: u64 = 0x15dc;

/// Win32 error codes the hook admission ladder reports through the TEB.
pub(crate) const ERROR_INVALID_HANDLE: u32 = 6;
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
pub(crate) const ERROR_HOOK_NEEDS_HMOD: u32 = 1428;
pub(crate) const ERROR_INVALID_FILTER_PROC: u32 = 1427;
pub(crate) const ERROR_GLOBAL_ONLY_HOOK: u32 = 1429;
pub(crate) const ERROR_INVALID_HOOK_HANDLE: u32 = 1404;
pub(crate) const ERROR_INVALID_HOOK_FILTER: u32 = 1426;
pub(crate) const ERROR_ACCESS_DENIED: u32 = 5;
pub(crate) const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;

/// Whether one ordinal belongs to the hook family. # C: O(1)
pub(crate) const fn claims(ordinal: u64) -> bool {
    matches!(ordinal, CALL_NEXT_HOOK | NOTIFY_WIN_EVENT | SET_WIN_EVENT_HOOK | SET_WINDOWS_HOOK
        | UNHOOK_WIN_EVENT | UNHOOK_WINDOWS_HOOK | UNHOOK_WINDOWS_HOOK_EX)
}

/// Win32 error one admission failure reports. # C: O(1)
pub(crate) const fn error_of(error: HookError) -> u32 {
    match error {
        HookError::InvalidFilterProc => ERROR_INVALID_FILTER_PROC,
        HookError::GlobalOnlyHook => ERROR_GLOBAL_ONLY_HOOK,
        HookError::AccessDenied => ERROR_ACCESS_DENIED,
        HookError::HookNeedsModule => ERROR_HOOK_NEEDS_HMOD,
        HookError::InvalidHookFilter => ERROR_INVALID_HOOK_FILTER,
        HookError::InvalidHandle => ERROR_INVALID_HOOK_HANDLE,
        HookError::InvalidParameter | HookError::NoMemory => ERROR_INVALID_PARAMETER,
    }
}

/// A hook procedure installed with a module base is stored relative to it, so
/// the address the chain walk hands back has the base added again.
/// # C: O(1)
pub(crate) fn relative_proc(proc_address: u64, instance: u64) -> Option<u64> {
    if instance == 0 { return Some(proc_address); }
    proc_address.checked_sub(instance)
}

/// Undo the module-relative encoding for a call. # C: O(1)
pub(crate) fn absolute_proc(stored: u64, instance: u64) -> Option<u64> {
    if instance == 0 { return Some(stored); }
    stored.checked_add(instance)
}

/// Which hook identifier a WinEvent installation uses. # C: O(1)
pub(crate) const fn win_event_id() -> i32 { WH_WINEVENT }

#[cfg(target_os = "oxide-kernel")]
#[path = "hook_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/hook_raw.rs"]
mod tests;
