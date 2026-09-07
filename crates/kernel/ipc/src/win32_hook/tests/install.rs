//! Installation admission ladder for window hooks and WinEvent hooks.
use super::*;

const PROC: u64 = 0x1_0000;
const MODULE: [u16; 4] = [b'u' as u16, b'3' as u16, b'2' as u16, 0];

#[test]
fn a_hook_without_a_procedure_is_refused_before_any_scope_rule() {
    assert_eq!(admit_window_hook(WH_CBT, None, 0x400, 0, &MODULE).err(), Some(HookError::InvalidFilterProc));
    assert_eq!(admit_window_hook(WH_KEYBOARD_LL, Some(9), 0, 0, &MODULE).err(), Some(HookError::InvalidFilterProc));
}

#[test]
fn the_global_only_identifiers_are_refused_for_a_single_thread() {
    for id in [WH_JOURNALRECORD, WH_JOURNALPLAYBACK, WH_KEYBOARD_LL, WH_MOUSE_LL, WH_SYSMSGFILTER] {
        assert_eq!(admit_window_hook(id, Some(9), 0x400, PROC, &MODULE).err(), Some(HookError::GlobalOnlyHook));
    }
    assert!(admit_window_hook(WH_CBT, Some(9), 0, PROC, &MODULE).is_ok());
}

#[test]
fn a_system_wide_journal_hook_is_refused_and_a_low_level_hook_drops_its_module() {
    assert_eq!(admit_window_hook(WH_JOURNALRECORD, None, 0x400, PROC, &MODULE).err(), Some(HookError::AccessDenied));
    assert_eq!(admit_window_hook(WH_JOURNALPLAYBACK, None, 0x400, PROC, &MODULE).err(), Some(HookError::AccessDenied));
    assert_eq!(admit_window_hook(WH_MOUSE_LL, None, 0x400, PROC, &MODULE), Ok(&[][..]));
}

#[test]
fn every_other_system_wide_window_hook_needs_a_module() {
    assert_eq!(admit_window_hook(WH_GETMESSAGE, None, 0, PROC, &MODULE).err(), Some(HookError::HookNeedsModule));
    assert_eq!(admit_window_hook(WH_GETMESSAGE, None, 0x400, PROC, &MODULE), Ok(&MODULE[..]));
}

#[test]
fn an_in_context_win_event_hook_needs_a_module_and_a_forward_event_range() {
    assert_eq!(admit_win_event_hook(1, 2, 0, None, WINEVENT_INCONTEXT, &MODULE).err(), Some(HookError::HookNeedsModule));
    assert_eq!(admit_win_event_hook(5, 4, 0x400, None, WINEVENT_INCONTEXT, &MODULE).err(), Some(HookError::InvalidHookFilter));
    assert_eq!(admit_win_event_hook(EVENT_MIN, EVENT_MAX, 0, None, WINEVENT_OUTOFCONTEXT, &MODULE), Ok(&MODULE[..]));
    assert_eq!(admit_win_event_hook(1, 2, 0x400, Some(9), WINEVENT_INCONTEXT, &MODULE), Ok(&[][..]));
}

fn request<'a>(id: i32, thread: Option<u64>, module: &'a [u16]) -> HookRequest<'a> {
    HookRequest { id, process: None, thread, owner: 1, event_min: EVENT_MIN, event_max: EVENT_MAX,
        flags: WINEVENT_INCONTEXT, proc_address: PROC, unicode: true, module }
}

#[test]
fn the_table_refuses_an_identifier_outside_the_chain_range() {
    assert_eq!(admit_table_install(&request(WH_MINHOOK - 1, None, &MODULE), 1, None).err(), Some(HookError::InvalidParameter));
    assert_eq!(admit_table_install(&request(WH_WINEVENT + 1, None, &MODULE), 1, None).err(), Some(HookError::InvalidParameter));
    assert_eq!(chain_index(WH_MINHOOK), Some(0));
    assert_eq!(chain_index(WH_WINEVENT), Some(NB_HOOKS - 1));
}

#[test]
fn a_low_level_hook_is_always_global_and_never_thread_bound() {
    assert_eq!(admit_table_install(&request(WH_MOUSE_LL, None, &[]), 1, None), Ok(HookScope::Global));
    assert_eq!(admit_table_install(&request(WH_MOUSE_LL, Some(9), &[]), 1, None).err(), Some(HookError::InvalidParameter));
}

#[test]
fn a_global_in_context_hook_needs_a_module_but_an_out_of_context_one_does_not() {
    assert_eq!(admit_table_install(&request(WH_CBT, None, &[]), 1, None).err(), Some(HookError::InvalidParameter));
    let mut out_of_context = request(WH_WINEVENT, None, &[]);
    out_of_context.flags = WINEVENT_OUTOFCONTEXT;
    assert_eq!(admit_table_install(&out_of_context, 1, None), Ok(HookScope::Global));
}

#[test]
fn a_thread_local_hook_may_omit_its_module_only_inside_the_installing_process() {
    assert_eq!(admit_table_install(&request(WH_CBT, Some(9), &[]), 1, Some(1)), Ok(HookScope::Thread(9)));
    assert_eq!(admit_table_install(&request(WH_CBT, Some(9), &[]), 1, Some(2)).err(), Some(HookError::InvalidParameter));
    assert_eq!(admit_table_install(&request(WH_CBT, Some(9), &MODULE), 1, Some(2)), Ok(HookScope::Thread(9)));
}
