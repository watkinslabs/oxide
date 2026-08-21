// Timekeeping core callbacks (`32a§5` step 14, `32a§7`, `23`).
//
// Module manifest:
// - `arith`: counter-delta and per-clock sleep accounting, pure and ungated.
// - `tests`: the arithmetic and the injected-sleep clock effects.
//
// The pair runs with interrupts disabled and one CPU online. Suspend records
// the counter and persistent clock and stops serving hardware readings;
// resume prefers a nonstop counter for ordinary suspend, and uses persistent
// time when the counter stopped or the machine cold-booted into hibernate
// restore.

pub mod arith;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use sync::{Spinlock, TaskList};

pub use arith::{account, cycle_delta, cycles_to_ns, persistent_delta_ns, resume_measure, select_sleep_ns,
    should_inject, sleep_ns, Clocksource, SleepAccount, SleepMeasure};

/// Platform persistent-clock reader. Absolute Unix nanoseconds; `None` means
/// no trustworthy reading is available.
pub type PersistentClock = fn() -> Option<u64>;

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
/// One platform owner installed at boot (CMOS on x86, PL031 on ARM).
static PERSISTENT_CLOCK: Spinlock<Option<PersistentClock>, TaskList> = Spinlock::new(None);
static PERSISTENT_AT_SUSPEND: AtomicU64 = AtomicU64::new(0);
static PERSISTENT_AT_SUSPEND_VALID: AtomicBool = AtomicBool::new(false);
/// This transaction will resume in a new monotonic-counter epoch.
static HIBERNATION_MEASUREMENT: AtomicBool = AtomicBool::new(false);

/// Install the machine's sole persistent-clock reader. # C: O(1)
/// # Ctx: boot CPU, before system-sleep entry
pub fn set_persistent_clock(reader: PersistentClock) -> bool {
    let mut slot = PERSISTENT_CLOCK.lock();
    if slot.is_some() { return false; }
    *slot = Some(reader);
    true
}

/// Read the canonical persistent clock. # C: O(1)
pub fn persistent_clock_ns() -> Option<u64> {
    let reader = *PERSISTENT_CLOCK.lock();
    reader.and_then(|read| read())
}

/// Mark the pending syscore resume as returning from a cold hibernate image.
/// Called only after the architecture continuation reports its restored side;
/// the original-side failure/unwind path retains ordinary suspend selection.
/// # C: O(1)
pub fn resume_from_hibernation() { HIBERNATION_MEASUREMENT.store(true, Ordering::Release); }

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
    match persistent_clock_ns() {
        Some(value) => {
            PERSISTENT_AT_SUSPEND.store(value, Ordering::Release);
            PERSISTENT_AT_SUSPEND_VALID.store(true, Ordering::Release);
        }
        None => PERSISTENT_AT_SUSPEND_VALID.store(false, Ordering::Release),
    }
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
    let monotonic_ns = sleep_ns(&PLATFORM_CLOCKSOURCE, at_suspend, now);
    let persistent_then = PERSISTENT_AT_SUSPEND_VALID.load(Ordering::Acquire)
        .then(|| PERSISTENT_AT_SUSPEND.load(Ordering::Acquire));
    let measure = resume_measure(HIBERNATION_MEASUREMENT.load(Ordering::Acquire));
    let ns = select_sleep_ns(measure, monotonic_ns, persistent_then, persistent_clock_ns());
    // Clearing the flag before the injection would let a reader in between see
    // a live counter with the sleep not yet accounted, which is the one moment
    // the monotonic clock could be observed jumping.
    if should_inject(ns) { crate::state::account_suspend(ns); }
    HIBERNATION_MEASUREMENT.store(false, Ordering::Release);
    PERSISTENT_AT_SUSPEND_VALID.store(false, Ordering::Release);
    SUSPENDED.store(false, Ordering::Release);
    ns
}

#[cfg(test)]
#[path = "suspend/tests.rs"]
mod tests;
