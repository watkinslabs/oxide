// Timekeeping core callbacks (`32a§5` step 14, `32a§7`, `23`).
//
// Module manifest:
// - `arith`: counter-delta and per-clock sleep accounting, pure and ungated.
// - `tests`: the arithmetic and the injected-sleep clock effects.
//
// The pair runs with interrupts disabled and one CPU online. Suspend records
// the counter and stops serving hardware readings; resume reads the counter
// again, converts the distance to nanoseconds, and hands that to the clock
// state as one sleep interval. A counter that stopped across the sleep yields
// no distance and injects nothing, which is the honest answer — the machine
// has no other measurement of how long it was away.

pub mod arith;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub use arith::{account, cycle_delta, cycles_to_ns, should_inject, sleep_ns, Clocksource, SleepAccount};

/// The counter the platform monotonic reading comes from. It already reads in
/// nanoseconds at full width, so no scaling is applied; the descriptor still
/// carries the shape so the arithmetic is the same one a narrow counter needs.
pub const PLATFORM_CLOCKSOURCE: Clocksource = Clocksource::nanoseconds();

/// Set across the sleep. While set, the clock readings are the ones frozen at
/// suspend rather than fresh hardware reads.
static SUSPENDED: AtomicBool = AtomicBool::new(false);
/// Counter reading taken at suspend, the origin of the sleep measurement.
static AT_SUSPEND: AtomicU64 = AtomicU64::new(0);
/// Reading served while suspended, so a caller in the window sees a clock that
/// has stopped rather than one that jumps.
static FROZEN_NS: AtomicU64 = AtomicU64::new(0);

/// Whether the timekeeper is inside a sleep. # C: O(1)
pub fn timekeeping_suspended() -> bool { SUSPENDED.load(Ordering::Acquire) }

/// Reading served in place of a hardware read while suspended. # C: O(1)
pub fn frozen_monotonic_ns() -> u64 { FROZEN_NS.load(Ordering::Acquire) }

/// Core-callback suspend: freeze the readers and record the counter.
///
/// Cannot refuse. The reference's failure paths here are all in code this
/// kernel does not have (a watchdog list, a persistent-clock read that can
/// fail); inventing one would be a refusal nothing produces.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
pub fn timekeeping_suspend() {
    let now = crate::platform::raw_monotonic_ns();
    AT_SUSPEND.store(now, Ordering::Release);
    FROZEN_NS.store(now, Ordering::Release);
    SUSPENDED.store(true, Ordering::Release);
}

/// Core-callback resume: measure the sleep and hand it to the clock state.
///
/// Returns the nanoseconds injected, zero when the counter could not measure
/// the sleep.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
pub fn timekeeping_resume() -> u64 {
    let at_suspend = AT_SUSPEND.load(Ordering::Acquire);
    let now = crate::platform::raw_monotonic_ns();
    let ns = sleep_ns(&PLATFORM_CLOCKSOURCE, at_suspend, now);
    // Clearing the flag before the injection would let a reader in between see
    // a live counter with the sleep not yet accounted, which is the one moment
    // the monotonic clock could be observed jumping.
    if should_inject(ns) { crate::state::account_suspend(ns); }
    SUSPENDED.store(false, Ordering::Release);
    ns
}

#[cfg(test)]
#[path = "suspend/tests.rs"]
mod tests;
