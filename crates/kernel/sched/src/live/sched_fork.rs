// Linux `sched_fork()` scheduler-parameter inheritance for a freshly built
// clone. Split out of `spawn.rs` so both arch fork paths share ONE copy of
// the rule (docs/53 "one place" / no split source of truth).
//
// Linux `sched_fork`: a child inherits the parent's
// policy, RT priority, nice and load weight; `sched_reset_on_fork` then
// demotes an RT/DEADLINE child to `SCHED_NORMAL` at nice 0 (and lifts a
// negative-nice child to nice 0), and the flag is CLEARED on the child so it
// applies exactly one generation deep.

use core::sync::atomic::Ordering;

use crate::cputime::NICE_0_WEIGHT;
use crate::task::{SchedClass, SchedPolicy, SchedPriority, Task, TaskSched};

/// `SCHED_NORMAL` / `SCHED_OTHER`.
const SCHED_NORMAL: u32 = 0;

/// A `SCHED_DEADLINE` task cannot fork.
///
/// The child would inherit a reservation that was admitted once, for one task;
/// letting it through would duplicate admitted bandwidth on every clone and
/// silently invalidate every other deadline task's guarantee. Setting
/// `SCHED_RESET_ON_FORK` first is the supported way to fork one: the child then
/// drops to `SCHED_NORMAL` and carries no reservation at all.
/// # C: O(1)
pub fn dl_fork_refused(parent: &Task) -> bool {
    let state = parent.priority_snapshot();
    state.policy == crate::task::TaskPolicy::Deadline && !state.reset_on_fork
}

/// Copy the parent's scheduling parameters onto a not-yet-published child and
/// apply `sched_reset_on_fork`.
///
/// `child` is local to the clone path and has no other reader yet; `parent` is
/// the running task on this CPU (single-mutator per `13§5`).
/// # C: O(1)
pub fn inherit_sched_params(child: &mut Task, parent: &Task) {
    let (state, parent_uclamp, parent_se) = parent.sched_fork_snapshot();
    let reset = state.reset_on_fork;
    let mut policy = state.policy.code();
    let nice = state.static_prio.nice().unwrap_or(0);
    // The per-CPU idle class is never inherited by a user clone.
    let mut class = match state.normal_prio {
        SchedPriority::Deadline => SchedClass::Deadline,
        SchedPriority::PosixRt(_) => SchedClass::Rt {
            prio: state.rt_priority,
            policy: if state.policy == crate::task::TaskPolicy::Rr { SchedPolicy::Rr }
                    else { SchedPolicy::Fifo },
        },
        SchedPriority::Fair(_) => SchedClass::Normal {
            weight: crate::cputime::nice_to_weight(nice as i8),
        },
        SchedPriority::NtFixed(_) | SchedPriority::Idle => {
            SchedClass::Normal { weight: NICE_0_WEIGHT }
        }
    };

    // A deadline child never carries the parent's reservation: it is either
    // refused outright (`dl_fork_refused`) or reset to the fair class here, and
    // its entity starts empty either way.
    if matches!(class, SchedClass::Deadline) {
        policy = SCHED_NORMAL;
        class = SchedClass::Normal { weight: NICE_0_WEIGHT };
    }

    if reset {
        if matches!(class, SchedClass::Rt { .. }) {
            policy = SCHED_NORMAL;
            class = SchedClass::Normal { weight: NICE_0_WEIGHT };
        } else if nice < 0 {
            class = SchedClass::Normal { weight: NICE_0_WEIGHT };
        }
    }

    // Linux `dup_task_struct` copies `cpus_mask`/`user_cpus_ptr` wholesale, and
    // `sched_reset_on_fork` does NOT clear them — affinity is inherited by every
    // clone, thread included. Without this a `CPUAffinity=` unit, a `taskset`
    // shell, or any `pthread_create` after `sched_setaffinity` silently escapes
    // the mask on the very next fork.
    child.cpus_allowed.store(parent.cpus_allowed.load(Ordering::Acquire), Ordering::Release);
    child.user_cpus_allowed.store(parent.user_cpus_allowed.load(Ordering::Acquire), Ordering::Release);
    child.cpuset_cpus_allowed.store(parent.cpuset_cpus_allowed.load(Ordering::Acquire), Ordering::Release);

    // `dup_task_struct` copies `se.slice`/`custom_slice` and `uclamp_req`;
    // `sched_reset_on_fork` puts both back to the class defaults
    // (via `uclamp_fork`), and `uclamp_post_fork`
    // then re-applies the RT 100%-boost default to a non-user-defined
    // `UCLAMP_MIN`.
    let (uc_min, uc_max, uc_ud) = if reset {
        (0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0)
    } else {
        (parent_uclamp.min(), parent_uclamp.max(), parent_uclamp.user_defined())
    };
    let uc_min = if matches!(class, SchedClass::Rt { .. }) && uc_ud & 1 == 0 {
        crate::sched_enc::UCLAMP_CAPACITY_SCALE
    } else { uc_min };
    child.sched = TaskSched::new(class, crate::sched_enc::RR_TIMESLICE_TICKS,
                                 crate::sched_enc::UCLAMP_CAPACITY_SCALE);
    child.sched.store_nice(state.static_prio.nice().unwrap_or(0) as i8);
    child.sched.store_normal_class(class, policy);
    child.sched.store_uclamp(crate::task::SchedUclamp::new(uc_min, uc_max, uc_ud)
        .expect("fork-derived utilization clamps remain canonical"));
    child.sched.se.slice.store(
        if reset { 0 } else { parent_se.slice }, Ordering::Release);
    child.sched.se.custom_slice.store(
        !reset && parent_se.custom_slice, Ordering::Release);

    // `__setscheduler_params` runs for the child too (
    // via `sched_fork`), so a child that inherits — or is reset to — an RT
    // policy carries zero timer slack, and one reset to a fair policy gets its
    // default back rather than the parent's zero.
    if child.is_rt_or_dl_policy() {
        child.security.timer_slack_ns.store(0, Ordering::Release);
    } else if child.security.timer_slack_ns.load(Ordering::Acquire) == 0 {
        child.security.timer_slack_ns.store(
            child.security.default_timer_slack_ns.load(Ordering::Acquire), Ordering::Release);
    }
    // `sched_reset_on_fork` is one-shot: the child starts clean.
    child.sched.store_reset_on_fork(false);
}
