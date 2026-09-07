//! Hook registry access. The registry is the canonical owner; this module
//! resolves the caller and enters the procedure the walk names.
use super::super::*;
use ipc::win32_hook::{Hook, HookError, HookRequest, HookScope, HookThread};

/// Desktop-wide hook registry, one per launch as the desktop is.
static HOOKS: Spinlock<ipc::win32_hook::HookRegistry, GuiLockClass> =
    Spinlock::new(ipc::win32_hook::HookRegistry::new());

/// Process one thread belongs to, for the same-process module rule.
/// # C: O(N_tasks)
pub(crate) fn hook_thread_process(thread: u64) -> Option<u64> {
    let tid = u32::try_from(thread).ok()?;
    sched::registry::lookup(tid).map(|task| task.thread_group.leader_pid().tid as u64)
}

/// Install one admitted hook. # C: O(N_threads + N_hooks)
pub(crate) fn hook_install(scope: HookScope, request: &HookRequest<'_>) -> Result<u32, HookError> {
    HOOKS.lock().install(scope, request)
}

/// Remove one hook by handle. # C: O(N_threads + N_hooks)
pub(crate) fn hook_remove(handle: u32) -> Result<(), HookError> { HOOKS.lock().remove(handle).map(|_| ()) }

/// Remove the calling thread's hook with one identifier and procedure.
/// # C: O(N_threads + N_hooks)
pub(crate) fn hook_remove_by_proc(thread: u64, id: i32, proc_address: u64) -> Result<(), HookError> {
    HOOKS.lock().remove_by_proc(thread, id, proc_address).map(|_| ())
}

/// Count of hooks one thread would run in a chain. # C: O(N_threads + N_hooks)
pub(crate) fn hook_chain_count(id: i32, caller: HookThread) -> usize { HOOKS.lock().chain_count(id, caller) }

/// The hook that follows the one being called, in the same chain.
/// # C: O(N_threads + N_hooks)
pub(crate) fn hook_next(current: u32, caller: HookThread) -> Option<Hook> {
    let registry = HOOKS.lock();
    let hook = registry.get(current)?;
    let (id, event) = (hook.id, hook.event_min);
    let next = registry.next_hook(id, Some(current), caller, event)?;
    registry.get(next.handle).cloned()
}

/// First hook of one chain for the calling thread. # C: O(N_threads + N_hooks)
pub(crate) fn hook_first(id: i32, caller: HookThread, event: u32) -> Option<Hook> {
    let registry = HOOKS.lock();
    let first = registry.next_hook(id, None, caller, event)?;
    registry.get(first.handle).cloned()
}

/// Enter one hook procedure. The stored address is relative to the hook's
/// module, which the client resolves; a hook with a module carries its base in
/// the record the client published. # C: O(1)
pub(crate) fn hook_call(hook: Hook, code: i32, wparam: u64, lparam: u64) -> u64 {
    crate::nt_rtl::begin_hook_callback(code as u32 as u64, wparam, lparam, hook.proc_address)
}

/// Announce one accessibility event into the WinEvent chain. The procedure
/// takes its hook handle, the event, the window, the two identifiers, the
/// announcing thread and the time it happened. # C: O(N_hooks)
pub(crate) fn hook_notify_win_event(event: u32, hwnd: u64, object_id: i32, child_id: i32, caller: HookThread) {
    let Some(hook) = hook_first(ipc::win32_hook::WH_WINEVENT, caller, event) else { return; };
    let time_ms = timekeeper::monotonic_ns().saturating_div(1_000_000);
    let _ = crate::nt_rtl::begin_win_event_callback(hook.handle as u64, event as u64, hwnd,
        object_id as u32 as u64, child_id as u32 as u64, caller.thread, time_ms, hook.proc_address);
}

/// Drop every hook an exiting thread installed or targeted. # C: O(N_threads + N_hooks)
pub(crate) fn hook_forget_thread(thread: u64) { HOOKS.lock().cleanup_thread(thread); }
