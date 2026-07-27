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

    child.nice.store(nice, Ordering::Release);
    child.policy.store(policy, Ordering::Release);
    // `sched_reset_on_fork` is one-shot: the child starts clean.
    child.sched_reset_on_fork.store(false, Ordering::Release);
    child.load_weight.store(match class {
        SchedClass::Normal { weight } => weight,
        _ => NICE_0_WEIGHT,
    }, Ordering::Release);
    child.set_sched_class(class);
}
