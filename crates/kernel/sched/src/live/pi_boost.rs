// Applying and undoing a PI-futex priority boost on a live task.
//
// The ORDERING rule (which class wins) is in the non-gated `crate::pi_prio`
// and is hosted-tested there; this file owns only the runqueue-visible half:
// save the base class once, move the task between rt/cfs trees, and restore.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::{SchedClass, Task};

pub use crate::pi_prio::{PI_NOT_BOOSTED, base_class, is_boosted};

/// Record a new BASE class for a task that may be boosted right now.
///
/// `sched_setscheduler` on a boosted task must not write `class_enc` directly:
/// the deboost would immediately overwrite it with the pre-boost value and the
/// caller's change would vanish. When boosted, the new base is parked here and
/// takes effect at deboost; when not boosted, this is exactly `set_class`.
/// # C: O(N_cpus · log N)
pub fn set_base_class(task: &Arc<Task>, new: SchedClass) {
    if !is_boosted(task) { super::runqueue::set_class(task, new); return; }
    task.pi_base_class.store(new.encode(), Ordering::Release);
    // Re-derive the boost against the new base: a base raised ABOVE the
    // inherited class must take effect now, or the task runs below the
    // priority userspace just asked for.
    let cur = task.sched_class();
    if crate::pi_prio::outranks(new, cur) { super::runqueue::set_class(task, new); }
}

/// Apply the boost computed by [`crate::pi_prio::boost_class`] over `waiters`.
///
/// Idempotent and re-entrant: calling it again as the waiter set changes
/// recomputes from the BASE class, so a departing top waiter lowers the boost
/// rather than leaving the owner permanently elevated.
/// # C: O(N_waiters + N_cpus · log N)
pub fn apply_boost(task: &Arc<Task>, waiters: &[SchedClass]) {
    let base = base_class(task);
    match crate::pi_prio::boost_class(base, waiters) {
        Some(boosted) => {
            // Save the base on the FIRST boost only; a re-boost must not
            // record the already-inherited class as the base, which would
            // make the elevation permanent.
            let _ = task.pi_base_class.compare_exchange(
                PI_NOT_BOOSTED, base.encode(), Ordering::AcqRel, Ordering::Acquire);
            if task.sched_class() != boosted { super::runqueue::set_class(task, boosted); }
        }
        None => deboost(task),
    }
}

/// Drop any PI boost and return `task` to its base class.
/// # C: O(N_cpus · log N)
pub fn deboost(task: &Arc<Task>) {
    let saved = task.pi_base_class.swap(PI_NOT_BOOSTED, Ordering::AcqRel);
    if saved == PI_NOT_BOOSTED { return; }
    let base = SchedClass::decode(saved);
    if task.sched_class() != base { super::runqueue::set_class(task, base); }
}
