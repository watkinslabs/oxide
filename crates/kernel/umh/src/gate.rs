// The suspend/hibernate gate and running-helper accounting.
//
// A helper is a userspace process. Once userspace has been frozen for suspend
// or hibernate, starting one would resurrect a process into a frozen system, so
// the gate closes first and every submission is refused with EBUSY until it
// reopens. The gate is also closed at boot: nothing may exec a helper before
// userspace exists.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicPtr, Ordering};

use syscall::errno::Errno;

use crate::uapi::{RUNNING_HELPERS_TIMEOUT_MS, UmhDisableDepth};

/// Current depth. Boot value is `Disabled`: userspace does not exist yet.
static DEPTH: AtomicU8 = AtomicU8::new(UmhDisableDepth::Disabled as u8);

/// In-flight helpers. `usermodehelper_disable` waits for this to reach zero so
/// a suspend cannot race a helper that is mid-exec.
static RUNNING: AtomicU32 = AtomicU32::new(0);

/// Installed sleep-a-tick hook used while draining. Absent (hosted, early boot)
/// the drain degrades to a bounded spin over the same iteration budget, so the
/// decision it feeds is identical either way.
type YieldFn = fn();
static YIELD_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the "sleep one millisecond" primitive the drain loop uses.
/// # C: O(1)
pub fn set_yield_hook(f: YieldFn) {
    YIELD_HOOK.store(f as *mut (), Ordering::Release);
}

fn do_yield() {
    let p = YIELD_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: the slot only ever holds a `YieldFn` installed by set_yield_hook, and is never cleared, so a non-null value is a live fn pointer of that exact type.
    let f: YieldFn = unsafe { core::mem::transmute::<*mut (), YieldFn>(p) };
    f();
}

/// Current gate state. # C: O(1)
pub fn depth() -> UmhDisableDepth {
    UmhDisableDepth::from_u8(DEPTH.load(Ordering::Acquire))
}

/// True while the gate refuses new helpers. # C: O(1)
pub fn usermodehelper_disabled() -> bool { depth().is_disabled() }

/// Number of helpers currently in flight. # C: O(1)
pub fn running_helpers() -> u32 { RUNNING.load(Ordering::Acquire) }

/// Linux `helper_lock`: account one submission in flight. Taken BEFORE the gate
/// is read so a concurrent disable either sees this helper and waits for it, or
/// closes the gate first and this submission is refused. # C: O(1)
pub fn helper_lock() { RUNNING.fetch_add(1, Ordering::AcqRel); }

/// Linux `helper_unlock`. # C: O(1)
pub fn helper_unlock() {
    // Saturating: an unbalanced unlock must not wrap the counter to u32::MAX and
    // wedge every future disable.
    let _ = RUNNING.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |v| Some(v.saturating_sub(1)));
}

/// Set the depth without waiting for in-flight helpers (Linux
/// `__usermodehelper_set_disable_depth`). # C: O(1)
pub fn set_disable_depth(d: UmhDisableDepth) {
    DEPTH.store(d as u8, Ordering::Release);
}

/// Close the gate to `d` and wait for in-flight helpers to drain.
/// Returns 0 on success, `-EINVAL` when asked to "disable" to the enabled
/// state, and `-EAGAIN` (with the gate REOPENED) when the drain timed out.
/// # C: O(timeout)
pub fn __usermodehelper_disable(d: UmhDisableDepth) -> i32 {
    if !d.is_disabled() { return -(Errno::Einval.as_i32()); }
    set_disable_depth(d);
    if drain_running_helpers() { return 0; }
    set_disable_depth(UmhDisableDepth::Enabled);
    -(Errno::Eagain.as_i32())
}

/// Poll until no helper is in flight or the timeout expires. True = drained.
/// # C: O(timeout)
fn drain_running_helpers() -> bool {
    for _ in 0..RUNNING_HELPERS_TIMEOUT_MS {
        if running_helpers() == 0 { return true; }
        do_yield();
    }
    running_helpers() == 0
}

/// Close the gate fully and wait for in-flight helpers (Linux
/// `usermodehelper_disable`). # C: O(timeout)
pub fn usermodehelper_disable() -> i32 {
    __usermodehelper_disable(UmhDisableDepth::Disabled)
}

/// Reopen the gate (Linux `usermodehelper_enable`). Called once userspace is
/// running, and again on resume. # C: O(1)
pub fn usermodehelper_enable() {
    set_disable_depth(UmhDisableDepth::Enabled);
}

/// Test-only: put the gate back in its boot state so one test cannot leak
/// its gate change into the next.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    DEPTH.store(UmhDisableDepth::Disabled as u8, Ordering::Release);
    RUNNING.store(0, Ordering::Release);
}
