//! Hook registry access. The registry is the canonical owner; this module
//! resolves the caller and enters the procedure the walk names.
use super::super::*;
use ipc::win32_hook::{Hook, HookError, HookRequest, HookScope, HookThread};

/// Desktop-wide hook registry, one per launch as the desktop is.
static HOOKS: Spinlock<super::hook_state::State, GuiLockClass> =
    Spinlock::new(super::hook_state::State::new());

/// Completion routes back to the announcing thread's saved notification.
pub(crate) const CALLBACK_WIN_EVENT: u64 = 0x82;

/// Process one thread belongs to, for the same-process module rule.
/// # C: O(N_tasks)
pub(crate) fn hook_thread_process(thread: u64) -> Option<u64> {
    let tid = u32::try_from(thread).ok()?;
    sched::registry::lookup(tid).map(|task| task.thread_group.leader_pid().tid as u64)
}

/// Install one admitted hook. # C: O(N_threads + N_hooks)
pub(crate) fn hook_install(scope: HookScope, request: &HookRequest<'_>) -> Result<u32, HookError> {
    HOOKS.lock().registry.install(scope, request)
}

/// Remove one hook by handle. # C: O(N_threads + N_hooks)
pub(crate) fn hook_remove(handle: u32) -> Result<(), HookError> { HOOKS.lock().registry.remove(handle).map(|_| ()) }

/// Remove the calling thread's hook with one identifier and procedure.
/// # C: O(N_threads + N_hooks)
pub(crate) fn hook_remove_by_proc(thread: u64, id: i32, proc_address: u64) -> Result<(), HookError> {
    HOOKS.lock().registry.remove_by_proc(thread, id, proc_address).map(|_| ())
}

/// Count of hooks one thread would run in a chain. # C: O(N_threads + N_hooks)
pub(crate) fn hook_chain_count(id: i32, caller: HookThread) -> usize { HOOKS.lock().registry.chain_count(id, caller) }

/// The hook that follows the one being called, in the same chain.
/// # C: O(N_threads + N_hooks)
pub(crate) fn hook_next(current: u32, caller: HookThread) -> Option<Hook> {
    let state = HOOKS.lock();
    let registry = &state.registry;
    let hook = registry.get(current)?;
    let (id, event) = (hook.id, hook.event_min);
    let next = registry.next_hook(id, Some(current), caller, event)?;
    registry.get(next.handle).cloned()
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
pub(crate) fn hook_notify_win_event(event: u32, hwnd: u64, object_id: i32, child_id: i32, caller: HookThread) -> u64 {
    let notification = super::hook_event::Notification { event, hwnd, object_id, child_id,
        thread: caller.thread as u32, time: 0 };
    let Some(token) = HOOKS.lock().begin(caller, notification, None) else { return 0; };
    resume_event(token, caller.thread)
}

fn resume_event(token: u64, thread: u64) -> u64 {
    loop {
        let step = HOOKS.lock().step(token, thread);
        match step {
            Some(super::hook_state::Step::Call(hook, mut notification)) => {
                notification.time = timekeeper::monotonic_ns().saturating_div(1_000_000) as u32;
                if hook.flags & ipc::win32_hook::WINEVENT_INCONTEXT == 0 {
                    let _ = super::super::send::post_event(hook, notification);
                    continue;
                }
                let completion = sched::nt_callback::Completion { kind: CALLBACK_WIN_EVENT, argument: token };
                let status = super::hook_event::begin(&hook, notification, completion);
                if status == STATUS_PENDING { return status; }
            }
            Some(super::hook_state::Step::Done(resume)) => return resume.map_or(0, |resume| (resume.resume)(resume.token, Ok(0))),
            None => return 0,
        }
    }
}

/// Resume after the client callback; its result does not stop event delivery.
/// # C: O(N_threads + N_hooks + N_notifications); # Sleeps: usercopy
#[cfg(any(test, target_arch = "x86_64"))]
pub(crate) fn hook_complete_event(completion: sched::nt_callback::Completion, _: u64) -> u64 {
    let Some(task) = sched::live::current().filter(|task| task.is_nt_personality()) else { return 0; };
    resume_event(completion.argument, task.tid as u64)
}

/// Drop every hook an exiting thread installed or targeted. # C: O(N_threads + N_hooks)
pub(crate) fn hook_forget_thread(thread: u64) { HOOKS.lock().forget_thread(thread); }

/// Deliver one copied queued event; registration removal does not revoke queued data.
/// # C: O(module path); # Sleeps: usercopy
pub(crate) fn hook_deliver_queued(hook: &Hook, notification: super::HookNotification, completion: sched::nt_callback::Completion) -> u64 {
    super::hook_event::begin(hook, notification, completion)
}
