// CPU-affinity inheritance and mask composition. Linux `dup_task_struct`
// memcpy's `cpus_mask`/`user_cpus_ptr` into the child, and
// `sched_reset_on_fork` does NOT clear them; `cpuset_update_tasks_cpus`
// composes the cpuset with the user's own request rather than replacing it.
// Reference: Linux `kernel/fork.c`, `kernel/sched/core.c`, `kernel/cgroup/cpuset.c`.

use core::sync::atomic::Ordering;

use crate::affinity::compose;
use crate::live::sched_fork::inherit_sched_params;
use crate::task::{SchedClass, Task};

fn task(tid: u32) -> Task { Task::new(tid, "affinity-test", SchedClass::Normal { weight: 1024 }) }

/// A clone inherits the parent's effective mask. Without this, a
/// `CPUAffinity=` unit, a `taskset` shell, or any `pthread_create` after
/// `sched_setaffinity(2)` escapes the mask on the very next fork — the mask is
/// stored but not honoured.
#[test]
fn a_clone_inherits_the_parents_affinity_mask() {
    let parent = task(1);
    parent.cpus_allowed.store(0b0010, Ordering::Release);
    let child = task(2);
    assert_eq!(child.cpus_allowed.load(Ordering::Acquire), u64::MAX, "fresh task starts unpinned");
    inherit_sched_params(&child, &parent);
    assert_eq!(child.cpus_allowed.load(Ordering::Acquire), 0b0010);
}

/// The `sched_setaffinity(2)` request and the cpuset restriction are inherited
/// too, so the child's mask keeps composing the same way the parent's did.
#[test]
fn a_clone_inherits_the_user_request_and_the_cpuset() {
    let parent = task(1);
    parent.user_cpus_allowed.store(0b1010, Ordering::Release);
    parent.cpuset_cpus_allowed.store(0b0011, Ordering::Release);
    parent.cpus_allowed.store(compose(0b0011, 0b1010), Ordering::Release);
    let child = task(2);
    inherit_sched_params(&child, &parent);
    assert_eq!(child.user_cpus_allowed.load(Ordering::Acquire), 0b1010);
    assert_eq!(child.cpuset_cpus_allowed.load(Ordering::Acquire), 0b0011);
    assert_eq!(child.cpus_allowed.load(Ordering::Acquire), 0b0010);
}

/// `sched_reset_on_fork` resets policy and nice, never affinity — Linux only
/// demotes the scheduling class.
#[test]
fn reset_on_fork_does_not_clear_affinity() {
    let parent = task(1);
    parent.sched_reset_on_fork.store(true, Ordering::Release);
    parent.nice.store(-5, Ordering::Release);
    parent.cpus_allowed.store(0b0100, Ordering::Release);
    let child = task(2);
    inherit_sched_params(&child, &parent);
    assert_eq!(child.nice.load(Ordering::Acquire), 0, "reset_on_fork lifts a negative nice");
    assert_eq!(child.cpus_allowed.load(Ordering::Acquire), 0b0100, "affinity survives");
}

/// A fresh task with no cpuset and no user request runs anywhere.
#[test]
fn defaults_leave_a_task_unpinned() {
    let t = task(1);
    assert_eq!(t.cpus_allowed.load(Ordering::Acquire), u64::MAX);
    assert_eq!(t.cpuset_cpus_allowed.load(Ordering::Acquire), u64::MAX);
    assert_eq!(t.user_cpus_allowed.load(Ordering::Acquire), 0, "0 = never called setaffinity");
    assert!(!t.no_setaffinity.load(Ordering::Acquire));
    assert_eq!(compose(u64::MAX, 0), u64::MAX);
}
