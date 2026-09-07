//! Hook ordinal admission, error mapping and the module-relative encoding.
use super::*;

#[test]
fn the_family_claims_exactly_its_own_ordinals() {
    for ordinal in [CALL_NEXT_HOOK, NOTIFY_WIN_EVENT, SET_WIN_EVENT_HOOK, SET_WINDOWS_HOOK,
        UNHOOK_WIN_EVENT, UNHOOK_WINDOWS_HOOK, UNHOOK_WINDOWS_HOOK_EX] {
        assert!(claims(ordinal), "{ordinal:#x}");
    }
    assert!(!claims(0x133a));
    assert!(!claims(0));
}

#[test]
fn every_admission_failure_maps_to_the_error_the_call_reports() {
    assert_eq!(error_of(HookError::InvalidFilterProc), ERROR_INVALID_FILTER_PROC);
    assert_eq!(error_of(HookError::GlobalOnlyHook), ERROR_GLOBAL_ONLY_HOOK);
    assert_eq!(error_of(HookError::AccessDenied), ERROR_ACCESS_DENIED);
    assert_eq!(error_of(HookError::HookNeedsModule), ERROR_HOOK_NEEDS_HMOD);
    assert_eq!(error_of(HookError::InvalidHookFilter), ERROR_INVALID_HOOK_FILTER);
    assert_eq!(error_of(HookError::InvalidHandle), ERROR_INVALID_HOOK_HANDLE);
    assert_eq!(error_of(HookError::InvalidParameter), ERROR_INVALID_PARAMETER);
    assert_eq!(error_of(HookError::NoMemory), ERROR_INVALID_PARAMETER);
}

#[test]
fn a_procedure_is_stored_relative_to_the_module_it_came_from() {
    let base = 0x7fff_0000_0000;
    assert_eq!(relative_proc(base + 0x1234, base), Some(0x1234));
}

#[test]
fn a_procedure_with_no_module_is_stored_as_it_arrived() {
    assert_eq!(relative_proc(0x1234, 0), Some(0x1234));
}

#[test]
fn a_procedure_below_its_module_base_cannot_be_encoded() {
    assert_eq!(relative_proc(0x100, 0x1000), None);
}

#[test]
fn win_event_hooks_share_the_chain_past_the_last_window_hook() {
    assert_eq!(win_event_id(), ipc::win32_hook::WH_WINEVENT);
    assert_eq!(ipc::win32_hook::chain_index(win_event_id()), Some(ipc::win32_hook::NB_HOOKS - 1));
}

#[test]
fn the_window_handle_error_is_the_one_an_event_for_no_window_reports() {
    assert_eq!(ERROR_INVALID_WINDOW_HANDLE, 1400);
}
