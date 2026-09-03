// Applying and undoing a PI-futex priority boost on a live task.
//
// The ORDERING rule (which class wins) is in the non-gated `crate::pi_prio`
// and is hosted-tested there; this file owns only the runqueue-visible half:
// update normal state, move the task between class trees, and restore it.

use alloc::sync::Arc;
use crate::{SchedClass, Task};

pub use crate::pi_prio::{base_class, is_boosted};

/// Record a new BASE class for a task that may be boosted right now.
///
/// `sched_setscheduler` on a boosted task updates canonical normal state while
/// the stronger donated effective state remains active. The new normal state
/// takes effect at deboost, or immediately when it outranks the donation.
/// # C: O(N_cpus · log N)
pub fn set_base_class(task: &Arc<Task>, new: SchedClass) {
    let was_boosted = is_boosted(task);
    let before = task.sched_class();
    task.set_normal_sched_class(new);
    let after = task.sched_class();
    if !was_boosted || before != after { super::runqueue::set_class(task, after); }
}

/// Record a validated Linux policy and its base class as one task transaction.
/// # C: O(N_cpus · log N)
pub fn set_base_class_policy_controls(task: &Arc<Task>, new: SchedClass, policy: u32,
                                      clamp: crate::SchedUclamp, reset: bool) {
    let was_boosted = is_boosted(task);
    let before = task.sched_class();
    task.set_sched_policy_controls(new, policy, clamp, reset);
    let after = task.sched_class();
    // `store_normal_class` recomputes `max(normal, donor)`. Requeue only when
    // that effective result changed; a weaker configured change remains
    // latent until deboost and therefore leaves the donor's queue position.
    if !was_boosted || before != after { super::runqueue::requeue_current_class(task); }
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
        // A deadline boost borrows the waiter's deadline scheduling entity,
        // not merely its class rank. The current futex bridge passes class
        // descriptors only, so applying this as an ordinary class change
        // would enqueue an unadmitted owner with an empty deadline entity.
        // Keep the owner valid until owner-wide PI carries donor identities.
        Some(SchedClass::Deadline) if !matches!(base, SchedClass::Deadline) => {}
        Some(boosted) => {
            if task.sched_class() != boosted { super::runqueue::set_class(task, boosted); }
        }
        None => deboost(task),
    }
}

/// Drop any PI boost and return `task` to its base class.
/// # C: O(N_cpus · log N)
pub fn deboost(task: &Arc<Task>) {
    if !is_boosted(task) { return; }
    let base = base_class(task);
    if task.sched_class() != base {
        super::runqueue::set_class(task, base);
    } else {
        task.restore_normal_sched_class();
    }
}
