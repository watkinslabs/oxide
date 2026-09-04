// Priority-inheritance ordering rule for PI futexes (`FUTEX_LOCK_PI` and
// friends). Non-gated so the "which class wins" decision is hosted-tested; the
// requeue that applies it lives in `live::pi_boost`.
//
// A PI mutex owner runs at the highest RT/deadline priority of {its own base}
// ∪ {every task blocked on a mutex it owns}. Ordinary waiters all carry the
// same default PI key: nice and fair weight are not donated. Without PI, a
// high-priority
// waiter is held off by a low-priority owner that a mid-priority third task can
// preempt indefinitely — unbounded priority inversion, the whole reason
// `PTHREAD_PRIO_INHERIT` exists.

use crate::{SchedClass, SchedPolicy, Task};

/// One coherent rtmutex waiter-node key captured under TaskPi and its rq.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PiDonorKey {
    pub class: SchedClass,
    pub deadline: u64,
    pub special: bool,
}

/// Total order over scheduling classes, matching what `pick_next_task`
/// actually does: deadline first, then RT by priority, then fair, then idle.
/// Ordinary priorities deliberately have one common value; fair weight is a
/// runqueue property, not a PI waiter key.
/// # C: O(1)
const fn sched_rank(c: SchedClass) -> (u8, u32) {
    match c {
        SchedClass::Deadline          => (4, 0),
        SchedClass::Rt { prio, .. }   => (3, prio as u32),
        SchedClass::NtFixed { level, .. } => (2, level as u32),
        SchedClass::Normal { .. }     => (1, 0),
        SchedClass::Idle              => (0, 0),
    }
}

/// True iff scheduling class/RT priority `a` outranks `b`.
/// # C: O(1)
pub const fn outranks(a: SchedClass, b: SchedClass) -> bool {
    let (ka, va) = sched_rank(a);
    let (kb, vb) = sched_rank(b);
    ka > kb || (ka == kb && va > vb)
}

/// True when waiter `a` sorts before waiter `b` in a PI wait tree.
/// Deadline peers use their effective absolute deadlines; RT and NT-fixed
/// peers use their numeric priorities. Ordinary peers retain FIFO order
/// because their waiter key is the common normal-priority value.
/// # C: O(1)
pub fn donor_key_outranks(a: PiDonorKey, b: PiDonorKey) -> bool {
    let ac = a.class;
    let bc = b.class;
    let ar = waiter_rank(ac);
    let br = waiter_rank(bc);
    if ar != br { return ar > br; }
    match (ac, bc) {
        (SchedClass::Deadline, SchedClass::Deadline) =>
            crate::deadline::dl_time_before(a.deadline, b.deadline),
        (SchedClass::Rt { prio: ap, .. }, SchedClass::Rt { prio: bp, .. }) => ap > bp,
        (SchedClass::NtFixed { level: ap, .. }, SchedClass::NtFixed { level: bp, .. }) => ap > bp,
        _ => false,
    }
}

const fn waiter_rank(c: SchedClass) -> u8 {
    match c {
        SchedClass::Deadline => 3,
        SchedClass::Rt { .. } => 2,
        SchedClass::NtFixed { .. } => 1,
        SchedClass::Normal { .. } | SchedClass::Idle => 0,
    }
}

/// Effective class produced by one concrete top donor. `base_deadline` is the
/// owner's own absolute deadline, distinct from a borrowed donor deadline.
/// # C: O(1)
pub fn class_with_key(base: SchedClass, base_deadline: u64, key: PiDonorKey) -> SchedClass {
    let donated = key.class;
    let wins = match (donated, base) {
        (SchedClass::Deadline, SchedClass::Deadline) =>
            key.special || crate::deadline::dl_time_before(key.deadline, base_deadline),
        (SchedClass::Normal { .. } | SchedClass::Idle, _) => false,
        _ => outranks(donated, base),
    };
    if !wins { return base; }
    match donated {
        SchedClass::Rt { prio, .. } => {
            let policy = match base {
                SchedClass::Rt { policy, .. } => policy,
                _ => SchedPolicy::Fifo,
            };
            SchedClass::Rt { prio, policy }
        }
        other => other,
    }
}

/// Value-only helper for scheduler policy tests. Live PI passes a coherent
/// concrete top-donor key through [`class_with_key`].
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
#[cfg(test)]
pub fn boost_class(base: SchedClass, waiters: &[SchedClass]) -> Option<SchedClass> {
    let mut best = base;
    for &w in waiters {
        if matches!(w, SchedClass::Deadline | SchedClass::Rt { .. }
            | SchedClass::NtFixed { .. }) && outranks(w, best) {
            best = w;
        }
    }
    if best == base { return None; }
    Some(match best {
        SchedClass::Rt { prio, .. } => SchedClass::Rt { prio, policy: SchedPolicy::Fifo },
        other => other,
    })
}

/// The class `task` would run at with every PI boost removed — Linux's
/// `p->normal_prio` / `p->rt_priority` as opposed to the effective `p->prio`.
///
/// Anything reporting or reasoning about the task's OWN priority must read
/// this, never `sched_class()`: while a PI boost is applied, effective state
/// holds a priority borrowed from a waiter, and reporting that through
/// `sched_getparam` would tell userspace it had set a priority it never asked
/// for — and reading it back into `sched_setscheduler` would make the boost
/// permanent.
/// # C: O(1)
pub fn base_class(task: &Task) -> SchedClass {
    task.normal_sched_class()
}

/// True iff a PI boost is currently applied to `task`.
/// # C: O(1)
pub fn is_boosted(task: &Task) -> bool {
    task.sched_is_boosted()
}
