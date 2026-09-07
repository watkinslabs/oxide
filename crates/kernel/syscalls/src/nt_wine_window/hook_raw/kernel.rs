//! Hook ordinal wiring: usercopy, TEB error reporting and encoding only.
use super::*;
use alloc::vec::Vec;
use ipc::win32_hook::{admit_table_install, admit_win_event_hook, admit_window_hook, HookRequest,
    HookThread, EVENT_MAX, EVENT_MIN, WINEVENT_INCONTEXT};
use crate::nt_window as owner;

const TEB_LAST_ERROR_OFFSET: u64 = 0x68;
const UNICODE_STRING_LENGTH: u64 = 0;
const UNICODE_STRING_BUFFER: u64 = 8;
/// Longest module path one hook installation carries.
const MAX_MODULE_UNITS: usize = 260;

fn last_error(error: u32) {
    let Some(task) = sched::live::current().filter(|task| task.is_nt_personality()) else { return; };
    let teb = task.nt_teb();
    if teb == 0 { return; }
    if let Some(address) = teb.checked_add(TEB_LAST_ERROR_OFFSET) { let _ = uaccess::put_user_u32(address, error); }
}

fn caller() -> Option<HookThread> {
    let task = sched::live::current().filter(|task| task.is_nt_personality())?;
    Some(HookThread { thread: task.tid as u64, process: task.thread_group.leader_pid().tid as u64 })
}

fn module(string: u64) -> Vec<u16> {
    let mut units = Vec::new();
    if string == 0 { return units; }
    let (Ok(length), Ok(buffer)) = (uaccess::get_user_u16(string + UNICODE_STRING_LENGTH),
        uaccess::get_user_u64(string + UNICODE_STRING_BUFFER)) else { return units; };
    let count = (length as usize / 2).min(MAX_MODULE_UNITS);
    if buffer == 0 || units.try_reserve_exact(count).is_err() { return Vec::new(); }
    for index in 0..count {
        let Some(address) = buffer.checked_add(index as u64 * 2) else { return Vec::new(); };
        let Ok(unit) = uaccess::get_user_u16(address) else { return Vec::new(); };
        units.push(unit);
    }
    units
}

/// # C: O(hook owner work plus bounded usercopy)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if !claims(ordinal) { return None; }
    Some(match ordinal {
        SET_WINDOWS_HOOK => set_windows_hook(args),
        SET_WIN_EVENT_HOOK => set_win_event_hook(args),
        UNHOOK_WINDOWS_HOOK_EX | UNHOOK_WIN_EVENT => unhook(args[0]),
        UNHOOK_WINDOWS_HOOK => unhook_by_proc(args[0] as u32 as i32, args[1]),
        CALL_NEXT_HOOK => call_next(args[0], args[1] as u32 as i32, args[2], args[3]),
        NOTIFY_WIN_EVENT => notify(args[0] as u32, args[1], args[2] as u32 as i32, args[3] as u32 as i32),
        _ => 0,
    })
}

fn install(request: HookRequest<'_>, instance: u64) -> u64 {
    let Some(caller) = caller() else { last_error(ERROR_INVALID_PARAMETER); return 0; };
    let target = request.thread.and_then(owner::hook_thread_process);
    let scope = match admit_table_install(&request, caller.process, target) {
        Ok(scope) => scope,
        Err(error) => { last_error(error_of(error)); return 0; }
    };
    let _ = instance;
    match owner::hook_install(scope, &request) {
        Ok(handle) => handle as u64,
        Err(error) => { last_error(error_of(error)); 0 }
    }
}

fn set_windows_hook(args: &[u64]) -> u64 {
    let (instance, id, proc_address) = (args[0], args[3] as u32 as i32, args[4]);
    let thread = (args[2] as u32 != 0).then_some(args[2] as u32 as u64);
    let carried = module(args[1]);
    let stored = match admit_window_hook(id, thread, instance, proc_address, &carried) {
        Ok(stored) => stored.to_vec(),
        Err(error) => { last_error(error_of(error)); return 0; }
    };
    let Some(relative) = relative_proc(proc_address, if stored.is_empty() { 0 } else { instance }) else {
        last_error(ERROR_INVALID_PARAMETER); return 0;
    };
    install(HookRequest { id, process: None, thread, owner: caller().map_or(0, |caller| caller.thread),
        event_min: EVENT_MIN, event_max: EVENT_MAX, flags: WINEVENT_INCONTEXT, proc_address: relative,
        unicode: args[5] == 0, module: &stored }, instance)
}

fn set_win_event_hook(args: &[u64]) -> u64 {
    let (event_min, event_max, instance) = (args[0] as u32, args[1] as u32, args[2]);
    let Some(pid) = crate::nt_dispatch::stack_argument(6) else { last_error(ERROR_INVALID_PARAMETER); return 0; };
    let Some(tid) = crate::nt_dispatch::stack_argument(7) else { last_error(ERROR_INVALID_PARAMETER); return 0; };
    let Some(flags) = crate::nt_dispatch::stack_argument(8) else { last_error(ERROR_INVALID_PARAMETER); return 0; };
    let thread = (tid as u32 != 0).then_some(tid as u32 as u64);
    let carried = module(args[3]);
    let stored = match admit_win_event_hook(event_min, event_max, instance, thread, flags as u32, &carried) {
        Ok(stored) => stored.to_vec(),
        Err(error) => { last_error(error_of(error)); return 0; }
    };
    let Some(relative) = relative_proc(args[4], if stored.is_empty() { 0 } else { instance }) else {
        last_error(ERROR_INVALID_PARAMETER); return 0;
    };
    install(HookRequest { id: win_event_id(), process: (pid as u32 != 0).then_some(pid as u32 as u64),
        thread, owner: caller().map_or(0, |caller| caller.thread), event_min, event_max,
        flags: flags as u32, proc_address: relative, unicode: true, module: &stored }, instance)
}

fn unhook(handle: u64) -> u64 {
    let Ok(handle) = u32::try_from(handle) else { last_error(ERROR_INVALID_HOOK_HANDLE); return 0; };
    match owner::hook_remove(handle) {
        Ok(()) => 1,
        Err(error) => { last_error(error_of(error)); 0 }
    }
}

fn unhook_by_proc(id: i32, proc_address: u64) -> u64 {
    let Some(caller) = caller() else { last_error(ERROR_INVALID_PARAMETER); return 0; };
    match owner::hook_remove_by_proc(caller.thread, id, proc_address) {
        Ok(()) => 1,
        Err(error) => { last_error(error_of(error)); 0 }
    }
}

/// Continue the chain the current call is walking. The client publishes which
/// hook it is in, so the walk resumes past it. # C: O(hook owner work)
fn call_next(handle: u64, code: i32, wparam: u64, lparam: u64) -> u64 {
    let Some(caller) = caller() else { return 0; };
    let Ok(handle) = u32::try_from(handle) else { return 0; };
    let Some(next) = owner::hook_next(handle, caller) else { return 0; };
    owner::hook_call(next, code, wparam, lparam)
}

/// Announce one accessibility event. A chain with no hook for it is skipped
/// entirely, and a zero window is a parameter error. # C: O(hook owner work)
fn notify(event: u32, hwnd: u64, object_id: i32, child_id: i32) -> u64 {
    if hwnd == 0 { last_error(ERROR_INVALID_WINDOW_HANDLE); return 0; }
    let Some(caller) = caller() else { return 0; };
    if owner::hook_chain_count(win_event_id(), caller) == 0 { return 0; }
    owner::hook_notify_win_event(event, hwnd, object_id, child_id, caller);
    0
}
