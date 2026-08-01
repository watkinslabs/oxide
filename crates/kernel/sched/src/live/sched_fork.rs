// Linux `sched_fork()` scheduler-parameter inheritance for a freshly built
// clone. Split out of `spawn.rs` so both arch fork paths share ONE copy of
// the rule (docs/53 "one place" / no split source of truth).
//
// Linux `kernel/sched/core.c::sched_fork`: a child inherits the parent's
// policy, RT priority, nice and load weight; `sched_reset_on_fork` then
// demotes an RT/DEADLINE child to `SCHED_NORMAL` at nice 0 (and lifts a
// negative-nice child to nice 0), and the flag is CLEARED on the child so it
// applies exactly one generation deep.

use core::sync::atomic::Ordering;

use crate::cputime::NICE_0_WEIGHT;
use crate::task::{SchedClass, Task};

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
    matches!(parent.sched_class(), SchedClass::Deadline)
        && !parent.sched_reset_on_fork.load(Ordering::Acquire)
}

/// Copy the parent's scheduling parameters onto a not-yet-published child and
/// apply `sched_reset_on_fork`.
///
/// `child` is local to the clone path and has no other reader yet; `parent` is
/// the running task on this CPU (single-mutator per `13§5`).
/// # C: O(1)
pub fn inherit_sched_params(child: &Task, parent: &Task) {
    let reset = parent.sched_reset_on_fork.load(Ordering::Acquire);
    let mut policy = parent.policy.load(Ordering::Acquire);
    let mut nice = parent.nice.load(Ordering::Acquire);
    // The per-CPU idle class is never inherited by a user clone.
    let mut class = match parent.sched_class() {
        SchedClass::Idle => SchedClass::Normal { weight: NICE_0_WEIGHT },
        c => c,
    };

    // A deadline child never carries the parent's reservation: it is either
    // refused outright (`dl_fork_refused`) or reset to the fair class here, and
    // its entity starts empty either way.
    child.dl.clear();
    if matches!(class, SchedClass::Deadline) {
        policy = SCHED_NORMAL;
        nice = 0;
        class = SchedClass::Normal { weight: NICE_0_WEIGHT };
    }

    if reset {
        if matches!(class, SchedClass::Rt { .. }) {
            policy = SCHED_NORMAL;
            nice = 0;
            class = SchedClass::Normal { weight: NICE_0_WEIGHT };
        } else if nice < 0 {
            nice = 0;
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
    // (`kernel/sched/core.c:4834` and `uclamp_fork`), and `uclamp_post_fork`
    // then re-applies the RT 100%-boost default to a non-user-defined
    // `UCLAMP_MIN`.
    let (uc_min, uc_max, uc_ud) = if reset {
        (0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0)
    } else {
        (parent.uclamp_min.load(Ordering::Acquire), parent.uclamp_max.load(Ordering::Acquire),
         parent.uclamp_user_defined.load(Ordering::Acquire))
    };
    let uc_min = if matches!(class, SchedClass::Rt { .. }) && uc_ud & 1 == 0 {
        crate::sched_enc::UCLAMP_CAPACITY_SCALE
    } else { uc_min };
    child.uclamp_min.store(uc_min, Ordering::Release);
    child.uclamp_max.store(uc_max, Ordering::Release);
    child.uclamp_user_defined.store(uc_ud, Ordering::Release);
    child.sched_slice_ns.store(
        if reset { 0 } else { parent.sched_slice_ns.load(Ordering::Acquire) }, Ordering::Release);

    child.nice.store(nice, Ordering::Release);
    child.policy.store(policy, Ordering::Release);
    // `__setscheduler_params` runs for the child too (`kernel/sched/core.c:4828`,
    // via `sched_fork`), so a child that inherits — or is reset to — an RT
    // policy carries zero timer slack, and one reset to a fair policy gets its
    // default back rather than the parent's zero.
    if child.is_rt_or_dl_policy() {
        child.timer_slack_ns.store(0, Ordering::Release);
    } else if child.timer_slack_ns.load(Ordering::Acquire) == 0 {
        child.timer_slack_ns.store(
            child.default_timer_slack_ns.load(Ordering::Acquire), Ordering::Release);
    }
    // `sched_reset_on_fork` is one-shot: the child starts clean.
    child.sched_reset_on_fork.store(false, Ordering::Release);
    child.load_weight.store(match class {
        SchedClass::Normal { weight } => weight,
        _ => NICE_0_WEIGHT,
    }, Ordering::Release);
    child.set_sched_class(class);
}
