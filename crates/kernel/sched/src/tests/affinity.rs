// CPU-affinity inheritance and mask composition. Linux `dup_task_struct`
// memcpy's `cpus_mask`/`user_cpus_ptr` into the child, and
// `sched_reset_on_fork` does NOT clear them; `cpuset_update_tasks_cpus`
// composes the cpuset with the user's own request rather than replacing it.
//
// Also pins switch-time affinity eviction: a preempted-but-still-Runnable task
// whose mask lost the CPU it was running on must be re-queued on an allowed
// CPU, not back onto the one it may no longer use.

use core::sync::atomic::Ordering;

use crate::affinity::{compose, MaskChange::CpusetUpdate};
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
    parent.cpus_allowed.store(compose(0b0011, 0b1010, CpusetUpdate), Ordering::Release);
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
    assert_eq!(compose(u64::MAX, 0, CpusetUpdate), u64::MAX);
}

// ---- switch-time affinity eviction (`live::schedule::migrate`) ----
//
// Runqueues are built locally and reached through an injected accessor rather
// than installed into the per-CPU globals: that array only accepts writes for
// CPU 0 hosted and is process-global, so parallel test threads would collide.
// Each test below owns a distinct pair of CPU ids for the same reason (the
// parked-eviction slots are a process-global per-CPU array).

use alloc::sync::Arc;

use crate::TaskState;
use crate::live::runqueue::Runqueue;
use crate::live::rq_locate::{dequeue_from_owning_rq_with, enqueue_on_with};
use crate::live::schedule::migrate;
use crate::live::ttwu::select_task_rq_with;

/// Installed runqueues indexed by CPU id.
struct Cpus { rqs: alloc::vec::Vec<(u32, Runqueue)> }

impl Cpus {
    fn new(cpus: &[u32]) -> Self {
        Self { rqs: cpus.iter().map(|&c| {
            (c, Runqueue::new(c as u16, Arc::new(Task::new(0xE000 + c, "idle", SchedClass::Idle))))
        }).collect() }
    }
    fn get(&self, cpu: u32) -> Option<&Runqueue> {
        self.rqs.iter().find(|(c, _)| *c == cpu).map(|(_, rq)| rq)
    }
    /// CPU whose class tree holds `tid`, if any.
    fn holder(&self, tid: u32) -> Option<u32> {
        self.rqs.iter().find_map(|(c, rq)| {
            let mut inner = rq.inner.lock();
            let found = inner.remove(tid)?;
            found.on_rq.store(false, Ordering::Release);
            inner.enqueue(found);
            Some(*c)
        })
    }
}

/// A task executing on `cpu`: Runnable, queued nowhere. This is `prev` at the
/// moment `schedule()` decides where to put it back.
fn running_on(tid: u32, cpu: u32, allowed: u64) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "spinner", SchedClass::Normal { weight: 1024 }));
    t.cpu.store(cpu as u16, Ordering::Release);
    t.set_state(TaskState::Runnable);
    t.cpus_allowed.store(allowed, Ordering::Release);
    t
}

/// A CPU id at or above the mask width is unrepresentable, so no mask
/// constrains it — the bit test must not wrap around to bit 0.
#[test]
fn mask_bits_beyond_the_word_are_unconstrained() {
    assert!(migrate::cpu_permitted(0b0010, 1));
    assert!(!migrate::cpu_permitted(0b0010, 0));
    assert!(!migrate::cpu_permitted(0, 3));
    assert!(migrate::cpu_permitted(1, migrate::MASK_BITS), "id >= mask width is unconstrained");
}

/// THE BUG. A CPU-bound task whose mask just lost the CPU it is running on
/// must be sent elsewhere by `schedule()`. Before this, `put_prev_task` dropped
/// it straight back into the local tree and the next pick ran it on the very
/// CPU `sched_setaffinity(2)` had just forbidden — `taskset -p` against a
/// spinning thread was a no-op until that thread blocked.
#[test]
fn a_runnable_task_on_a_forbidden_cpu_is_evicted_to_an_allowed_one() {
    const HERE: u32 = 30;
    const THERE: u32 = 31;
    let cpus = Cpus::new(&[HERE, THERE]);
    let t = running_on(3001, HERE, 1u64 << THERE);
    assert_eq!(migrate::evict_target_with(&|c| cpus.get(c), HERE, &t), Some(THERE));
}

/// The common case costs a mask test and nothing else: a task still allowed
/// where it runs is re-queued locally, preserving cache warmth.
#[test]
fn a_task_still_allowed_here_is_not_evicted() {
    const HERE: u32 = 32;
    const THERE: u32 = 33;
    let cpus = Cpus::new(&[HERE, THERE]);
    let t = running_on(3002, HERE, (1u64 << HERE) | (1u64 << THERE));
    assert_eq!(migrate::evict_target_with(&|c| cpus.get(c), HERE, &t), None);
}

/// No allowed CPU has a runqueue: affinity is broken rather than the task
/// stranded. Upstream walks cpuset then the possible mask and ultimately
/// overrides the task's affinity — it never leaves a runnable task queued
/// nowhere.
#[test]
fn no_allowed_cpu_leaves_the_task_running_where_it_is() {
    const HERE: u32 = 34;
    let cpus = Cpus::new(&[HERE]);
    let t = running_on(3003, HERE, 1u64 << 40);
    assert_eq!(migrate::evict_target_with(&|c| cpus.get(c), HERE, &t), None);
    let empty = running_on(3004, HERE, 0);
    assert_eq!(migrate::evict_target_with(&|c| cpus.get(c), HERE, &empty), None);
}

/// The per-CPU idle task is never queued and never migrates (`13§2` inv. 7).
#[test]
fn the_idle_task_is_never_evicted() {
    const HERE: u32 = 35;
    const THERE: u32 = 36;
    let cpus = Cpus::new(&[HERE, THERE]);
    let idle = Arc::new(Task::new(3005, "idle", SchedClass::Idle));
    idle.cpu.store(HERE as u16, Ordering::Release);
    idle.cpus_allowed.store(1u64 << THERE, Ordering::Release);
    assert_eq!(migrate::evict_target_with(&|c| cpus.get(c), HERE, &idle), None);
}

/// Park then place: the evicted task lands in the DESTINATION tree and in no
/// other, and the slot is empty again for the next switch.
#[test]
fn a_parked_eviction_is_placed_on_the_destination_cpu() {
    const HERE: u32 = 37;
    const THERE: u32 = 38;
    let cpus = Cpus::new(&[HERE, THERE]);
    let t = running_on(3006, HERE, 1u64 << THERE);

    assert!(migrate::park(HERE, &t, THERE));
    assert_eq!(cpus.holder(3006), None, "parked, not queued — it is still on_cpu here");

    assert_eq!(migrate::place_parked_with(&|c| cpus.get(c), HERE), Some(THERE));
    assert_eq!(cpus.holder(3006), Some(THERE));
    assert_eq!(t.cpu.load(Ordering::Acquire), THERE as u16, "the enqueue re-homes the task");
    assert!(migrate::place_parked_with(&|c| cpus.get(c), HERE).is_none(), "slot drained");
}

/// A destination that lost its runqueue between the park and the placement
/// keeps the task runnable on the source CPU instead of dropping it.
#[test]
fn a_vanished_destination_falls_back_to_the_source_cpu() {
    const HERE: u32 = 39;
    const GONE: u32 = 40;
    let cpus = Cpus::new(&[HERE]);
    let t = running_on(3007, HERE, 1u64 << GONE);
    assert!(migrate::park(HERE, &t, GONE));
    assert_eq!(migrate::place_parked_with(&|c| cpus.get(c), HERE), Some(HERE));
    assert_eq!(cpus.holder(3007), Some(HERE));
}

/// One slot per CPU: a second park is refused so the caller re-queues locally
/// rather than overwriting — a task is never dropped on the floor.
#[test]
fn a_second_park_on_the_same_cpu_is_refused() {
    const HERE: u32 = 41;
    const THERE: u32 = 42;
    let a = running_on(3008, HERE, 1u64 << THERE);
    let b = running_on(3009, HERE, 1u64 << THERE);
    assert!(migrate::park(HERE, &a, THERE));
    assert!(!migrate::park(HERE, &b, THERE));
    assert_eq!(migrate::unpark(HERE).map(|t| t.tid), Some(3008));
    assert!(migrate::unpark(HERE).is_none());
}

/// `schedule()` re-picking `prev` (no switch, so nothing would drain the slot)
/// takes the parked task back and re-queues it locally.
#[test]
fn unpark_returns_the_task_for_local_requeue() {
    const HERE: u32 = 43;
    const THERE: u32 = 44;
    let cpus = Cpus::new(&[HERE, THERE]);
    let t = running_on(3010, HERE, 1u64 << THERE);
    assert!(migrate::park(HERE, &t, THERE));
    let back = migrate::unpark(HERE).expect("parked task returned");
    enqueue_on_with(&|c| cpus.get(c), HERE, back);
    assert_eq!(cpus.holder(3010), Some(HERE));
}

/// The QUEUED half of the mask-change relocation (`relocate_for_affinity`):
/// a task sitting in a now-forbidden CPU's tree is dequeued from THAT tree and
/// re-queued on an allowed one, ending up in exactly one tree.
#[test]
fn a_queued_task_relocates_off_a_forbidden_cpu() {
    const HERE: u32 = 45;
    const THERE: u32 = 46;
    let cpus = Cpus::new(&[HERE, THERE]);
    let t = running_on(3011, HERE, u64::MAX);
    enqueue_on_with(&|c| cpus.get(c), HERE, Arc::clone(&t));
    assert_eq!(cpus.holder(3011), Some(HERE));

    // The mask writer's new mask, then the relocation it performs.
    t.cpus_allowed.store(1u64 << THERE, Ordering::Release);
    let (moved, from) = dequeue_from_owning_rq_with(&|c| cpus.get(c), 3011)
        .expect("queued task is found on the CPU that owns it, not on the caller's");
    assert_eq!(from, HERE);
    assert!(!moved.on_rq.load(Ordering::Acquire), "the dequeue clears on_rq");
    let target = select_task_rq_with(&|c| cpus.get(c), HERE, &moved);
    assert_eq!(target, THERE, "placement honours the new mask");
    enqueue_on_with(&|c| cpus.get(c), target, moved);
    assert_eq!(cpus.holder(3011), Some(THERE));
}

/// A task whose mask still permits its current CPU is left alone by the same
/// relocation — no gratuitous migration on an unrelated cpuset write.
#[test]
fn a_queued_task_still_permitted_stays_put() {
    const HERE: u32 = 47;
    const THERE: u32 = 48;
    let cpus = Cpus::new(&[HERE, THERE]);
    let t = running_on(3012, HERE, (1u64 << HERE) | (1u64 << THERE));
    enqueue_on_with(&|c| cpus.get(c), HERE, Arc::clone(&t));
    assert!(migrate::cpu_permitted(t.cpus_allowed.load(Ordering::Acquire), HERE));
    assert_eq!(cpus.holder(3012), Some(HERE));
}
