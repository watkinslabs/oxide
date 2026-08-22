// Console participation in system sleep.
//
// The boot line owns one immutable policy for both halves of a transition.
// Keeping the decision here, beside the console registry, prevents the power
// sequence and individual console drivers from growing separate copies.

use core::sync::atomic::{AtomicBool, Ordering};

static SUSPEND_ENABLED: AtomicBool = AtomicBool::new(true);

/// Whether system sleep suspends and resumes registered consoles. # C: O(1)
pub fn suspend_enabled() -> bool { SUSPEND_ENABLED.load(Ordering::Acquire) }

/// Install the boot line's console-suspend policy. # C: O(1)
pub fn set_suspend_enabled(enabled: bool) { SUSPEND_ENABLED.store(enabled, Ordering::Release); }

/// Run one console power-management half when console suspend is enabled.
/// Returns whether `f` ran, so a hosted boundary test can prove the boot
/// policy reaches the operation rather than stopping at stored state. # C: O(1)
pub fn run_if_suspend_enabled(f: fn()) -> bool {
    if !suspend_enabled() { return false; }
    f();
    true
}
