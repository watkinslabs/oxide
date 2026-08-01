// Priority-inheritance ordering rule for PI futexes (`FUTEX_LOCK_PI` and
// friends). Non-gated so the "which class wins" decision is hosted-tested; the
// requeue that applies it lives in `live::pi_boost`.
//
// A PI mutex owner runs at the highest scheduling class of {its own base class}
// ∪ {every task blocked on a mutex it owns}. Without that, a high-priority
// waiter is held off by a low-priority owner that a mid-priority third task can
// preempt indefinitely — unbounded priority inversion, the whole reason
// `PTHREAD_PRIO_INHERIT` exists.

use core::sync::atomic::Ordering;

use crate::{SchedClass, SchedPolicy, Task};

/// Total order over scheduling classes, matching what `pick_next_task`
/// actually does: deadline first, then RT by priority, then fair by weight,
/// then idle. Returned as a sortable key so the boost rule is a plain `max`.
///
/// The fair-class rank uses `weight` (nice -20 → highest weight), which is the
/// value the CFS tree's own ordering derives from, so a nice(-20) waiter does
/// boost a nice(19) owner.
/// # C: O(1)
pub const fn class_rank(c: SchedClass) -> (u8, u32) {
    match c {
        SchedClass::Deadline          => (3, 0),
        SchedClass::Rt { prio, .. }   => (2, prio as u32),
        SchedClass::Normal { weight } => (1, weight),
        SchedClass::Idle              => (0, 0),
    }
}

/// True iff `a` outranks `b` for the purpose of boosting.
/// # C: O(1)
pub const fn outranks(a: SchedClass, b: SchedClass) -> bool {
    let (ka, va) = class_rank(a);
    let (kb, vb) = class_rank(b);
    ka > kb || (ka == kb && va > vb)
}

/// The class a PI-mutex owner must run at, given its own base class and the
/// classes of the tasks currently blocked on mutexes it owns.
///
/// Returns `None` when no boost is needed (the owner already outranks or
/// matches every waiter), so the caller can skip a runqueue move entirely.
///
/// An inherited RT class is always taken as `SCHED_FIFO`: the owner is running
/// borrowed priority for a bounded critical section and must not be forced off
/// it by an `SCHED_RR` quantum expiry, which would reintroduce the very
/// inversion the boost removes. Linux does the same by giving the boosted task
/// the waiter's priority without adopting its round-robin timeslice accounting.
/// # C: O(N_waiters)
pub fn boost_class(base: SchedClass, waiters: &[SchedClass]) -> Option<SchedClass> {
    let mut best = base;
    for &w in waiters {
        if outranks(w, best) { best = w; }
    }
    if best == base { return None; }
    Some(match best {
        SchedClass::Rt { prio, .. } => SchedClass::Rt { prio, policy: SchedPolicy::Fifo },
        other => other,
    })
}

/// Sentinel stored in `Task::pi_base_class` while the task carries no boost.
/// `SchedClass::Idle` encodes to `0`, so `0` cannot serve as "unset".
pub const PI_NOT_BOOSTED: u64 = u64::MAX;

/// The class `task` would run at with every PI boost removed — Linux's
/// `p->normal_prio` / `p->rt_priority` as opposed to the effective `p->prio`.
///
/// Anything reporting or reasoning about the task's OWN priority must read
/// this, never `sched_class()`: while a PI boost is applied, `class_enc` holds
/// a priority borrowed from a waiter, and reporting that through
/// `sched_getparam` would tell userspace it had set a priority it never asked
/// for — and reading it back into `sched_setscheduler` would make the boost
/// permanent.
/// # C: O(1)
pub fn base_class(task: &Task) -> SchedClass {
    match task.pi_base_class.load(Ordering::Acquire) {
        PI_NOT_BOOSTED => task.sched_class(),
        enc => SchedClass::decode(enc),
    }
}

/// True iff a PI boost is currently applied to `task`.
/// # C: O(1)
pub fn is_boosted(task: &Task) -> bool {
    task.pi_base_class.load(Ordering::Acquire) != PI_NOT_BOOSTED
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn rt(p: u8) -> SchedClass { SchedClass::Rt { prio: p, policy: SchedPolicy::Fifo } }
    const fn rr(p: u8) -> SchedClass { SchedClass::Rt { prio: p, policy: SchedPolicy::Rr } }
    const fn fair(w: u32) -> SchedClass { SchedClass::Normal { weight: w } }

    #[test]
    fn an_rt_waiter_boosts_a_fair_owner() {
        assert_eq!(boost_class(fair(1024), &[rt(50)]), Some(rt(50)));
    }

    #[test]
    fn a_fair_waiter_never_demotes_an_rt_owner() {
        assert_eq!(boost_class(rt(50), &[fair(1024)]), None);
    }

    #[test]
    fn the_highest_of_several_waiters_wins() {
        assert_eq!(boost_class(fair(1024), &[rt(10), rt(80), fair(88), rt(30)]), Some(rt(80)));
    }

    #[test]
    fn an_equal_priority_waiter_does_not_boost() {
        assert_eq!(boost_class(rt(50), &[rt(50), rt(20)]), None,
                   "an equal-rank waiter needs no boost; a pointless requeue would send the owner to the tail of its own bucket");
    }

    #[test]
    fn an_inherited_rr_priority_is_adopted_as_fifo() {
        assert_eq!(boost_class(fair(1024), &[rr(60)]), Some(rt(60)),
                   "a boosted owner must not be preempted by an RR quantum expiry mid-critical-section");
    }

    #[test]
    fn deadline_outranks_every_rt_priority() {
        assert_eq!(boost_class(rt(99), &[SchedClass::Deadline]), Some(SchedClass::Deadline));
        assert_eq!(boost_class(SchedClass::Deadline, &[rt(99)]), None);
    }

    #[test]
    fn a_higher_weight_fair_waiter_boosts_a_lower_weight_fair_owner() {
        assert_eq!(boost_class(fair(15), &[fair(88761)]), Some(fair(88761)),
                   "nice(-20) blocked behind nice(19) is still an inversion");
        assert_eq!(boost_class(fair(88761), &[fair(15)]), None);
    }

    #[test]
    fn no_waiters_means_no_boost() {
        assert_eq!(boost_class(fair(1024), &[]), None);
        assert_eq!(boost_class(rt(9), &[]), None);
    }

    #[test]
    fn idle_is_outranked_by_everything() {
        assert_eq!(boost_class(SchedClass::Idle, &[fair(1)]), Some(fair(1)));
        assert!(outranks(fair(1), SchedClass::Idle));
        assert!(!outranks(SchedClass::Idle, SchedClass::Idle));
    }
}
