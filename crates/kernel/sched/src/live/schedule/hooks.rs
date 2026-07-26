use core::sync::atomic::{AtomicPtr, Ordering};

/// `sched_switch` tracepoint hook (Linux `trace_sched_switch`). tracefs
/// installs it when the event is enabled and clears it when disabled, so the
/// switch hot path pays only one atomic load + null check while OFF. Fires on
/// every context switch with (prev_pid, prev_comm, next_pid, next_comm).
pub type SchedSwitchFn = fn(u32, &str, u32, &str);
static SCHED_SWITCH_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Aggregate metrics returned by `uninstall_global_with_stats`,
/// for smoke-driver bookkeeping.
#[derive(Copy, Clone, Debug, Default)]
pub struct RunStats {
    pub yields_total:       u32,
    pub voluntary_switches: u32,
    pub irq_switches:       u32,
}

/// Install (Some) / clear (None) the sched_switch tracepoint hook. # C: O(1)
pub fn install_sched_switch_hook(f: Option<SchedSwitchFn>) {
    let p = match f { Some(f) => f as *mut (), None => core::ptr::null_mut() };
    SCHED_SWITCH_HOOK.store(p, Ordering::Release);
}

/// Cheap gate for the switch hot path: true only while a tracer has the
/// hook installed. Lets the caller skip building `prev`/`next` comm
/// strings (a `Task::name` spinlock + copy each) when nobody is
/// listening, so the untraced switch still pays only the one atomic
/// load this file's top comment promises. # C: O(1)
#[inline]
pub(super) fn sched_switch_hook_installed() -> bool {
    !SCHED_SWITCH_HOOK.load(Ordering::Acquire).is_null()
}

/// Fire the sched_switch hook if installed. # C: O(1) when off
#[inline]
pub(super) fn fire_sched_switch(pp: u32, pc: &str, np: u32, nc: &str) {
    let raw = SCHED_SWITCH_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: raw was installed via `install_sched_switch_hook` with the
    // documented `fn(u32,&str,u32,&str)` signature; non-null implies a live fn.
    let f: SchedSwitchFn = unsafe { core::mem::transmute(raw) };
    f(pp, pc, np, nc);
}
