// The worker that drives zone updates. A zone read evaluates firmware and a
// cooling-device change writes it, so this runs in process context on the
// workqueue rather than from a timer callback, and re-arms itself from its own
// tail the way the other periodic sweeps in this kernel do.

#![cfg(target_os = "oxide-kernel")]

use crate::limits::NSEC_PER_MSEC;

/// How often the worker wakes when no zone has asked for anything sooner. A
/// zone's own cadence is finer than this; the floor exists so a zone whose
/// deadline was missed while the box was busy is still picked up.
const SWEEP_MS: u64 = 1_000;

/// Shortest re-arm the worker will use. A zone declaring a very fast cadence
/// must not turn the workqueue into a spin.
const MIN_DELAY_MS: u64 = 50;

/// Run every due zone, then re-arm. # C: O(N_due)
fn thermal_work(_arg: usize) {
    let now = timekeeper::monotonic_ns();
    crate::registry::tick(now);
    arm();
}

/// Queue the next sweep, at the earlier of the nearest zone deadline and the
/// sweep floor. # C: O(N_zones)
fn arm() {
    let now = timekeeper::monotonic_ns();
    let until_deadline = crate::registry::next_deadline_ns()
        .map(|deadline| deadline.saturating_sub(now) / NSEC_PER_MSEC)
        .unwrap_or(SWEEP_MS);
    let delay_ms = until_deadline.clamp(MIN_DELAY_MS, SWEEP_MS);
    sched::live::delayed_work::queue_delayed_work_on(0, thermal_work, 0, now, delay_ms);
}

/// Start the thermal worker. The terminal action is installed by the caller:
/// powering the machine down belongs to the power subsystem, and a class crate
/// that reached into it would invert the dependency the class sits under.
/// Called once from kernel init, after the workqueue exists. # C: O(N_zones)
pub fn start() {
    crate::registry::update_all(timekeeper::monotonic_ns());
    arm();
}
