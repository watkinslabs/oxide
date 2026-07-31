// A task queued on a REMOTE CPU's runqueue must be re-placed there, never
// duplicated onto the caller's runqueue.
//
// These build real `Runqueue` instances locally rather than installing into
// `GLOBALS` — that array only accepts writes for `this_cpu()` (always 0
// hosted) and is process-global, so parallel `cargo test` threads would
// collide. The accessor closure supplies the CPU->rq mapping instead, which is
// exactly what `global_for` does in production.

use super::*;
use core::sync::atomic::Ordering;
use crate::runqueue::RunqueueInner;
use crate::task::{SchedClass, SchedPolicy, Task};
use alloc::vec::Vec;

const CALLER_CPU: u32 = 0;
const REMOTE_CPU: u32 = 3;

fn normal_task(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "t", SchedClass::Normal { weight: 1024 }))
}

/// Two installed runqueues, indexed by CPU id.
struct Cpus {
    rqs: Vec<(u32, Runqueue)>,
}

impl Cpus {
    fn new(cpus: &[u32]) -> Self {
        let rqs = cpus.iter().map(|&c| {
            (c, Runqueue::new(c as u16, Arc::new(Task::new(1000 + c, "idle", SchedClass::Idle))))
        }).collect();
        Self { rqs }
    }
    fn get(&self, cpu: u32) -> Option<&Runqueue> {
        self.rqs.iter().find(|(c, _)| *c == cpu).map(|(_, rq)| rq)
    }
    /// How many of the installed runqueues hold `tid` in a class tree.
    fn trees_holding(&self, tid: u32) -> usize {
        self.rqs.iter().filter(|(_, rq)| {
            let mut inner = rq.inner.lock();
            let found = inner.remove(tid);
            let held = found.is_some();
            // Put it back so the probe is non-destructive.
            if let Some(t) = found { t.on_rq.store(false, Ordering::Release); inner.enqueue(t); }
            held
        }).count()
    }
}

fn enqueue_on(cpus: &Cpus, cpu: u32, task: Arc<Task>) {
    let rq = cpus.get(cpu).expect("test cpu installed");
    let mut inner = rq.inner.lock();
    inner.enqueue(task);
    rq.publish_nr_running(inner.nr_running());
}

#[test]
fn sanity_enqueue_puts_task_in_exactly_one_tree() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(7);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());
    assert_eq!(cpus.trees_holding(7), 1);
    assert!(t.on_rq.load(Ordering::Acquire));
}

/// The core hazard: `set_class` on a task sitting on ANOTHER CPU's runqueue
/// must not leave the same `Arc` in two trees. Pre-fix this failed with the
/// task present in both the remote tree and the caller's tree — two CPUs could
/// then pick and run it simultaneously.
#[test]
fn set_class_on_remote_queued_task_never_double_enqueues() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(11);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    set_class_with(&|c| cpus.get(c), &t, SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });

    assert_eq!(cpus.trees_holding(11), 1,
        "task is queued on more than one runqueue: two CPUs can run it at once");
}

/// It must stay on the runqueue it was already on — re-placing it on the
/// caller's CPU is an unauthorised migration (Linux `sched_change_end` uses
/// `task_rq(p)`).
#[test]
fn set_class_keeps_the_task_on_its_own_runqueue() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(12);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    set_class_with(&|c| cpus.get(c), &t, SchedClass::Rt { prio: 20, policy: SchedPolicy::Fifo });

    let remote = cpus.get(REMOTE_CPU).unwrap();
    let caller = cpus.get(CALLER_CPU).unwrap();
    assert_eq!(remote.inner.lock().nr_running(), 1, "task left its own runqueue");
    assert_eq!(caller.inner.lock().nr_running(), 0, "task was migrated to the caller's CPU");
}

#[test]
fn set_class_actually_applies_the_new_class() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(13);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    set_class_with(&|c| cpus.get(c), &t, SchedClass::Rt { prio: 42, policy: SchedPolicy::Fifo });

    assert!(matches!(t.sched_class(), SchedClass::Rt { prio: 42, .. }),
        "class change was lost");
    assert!(t.on_rq.load(Ordering::Acquire), "task must be back on a runqueue");
}

/// The requeue must land in the tree belonging to the NEW class, so the
/// scheduler finds it where it now belongs.
#[test]
fn set_class_requeues_into_the_new_class_tree() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(14);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    set_class_with(&|c| cpus.get(c), &t, SchedClass::Rt { prio: 60, policy: SchedPolicy::Fifo });

    let remote = cpus.get(REMOTE_CPU).unwrap();
    let mut inner = remote.inner.lock();
    let picked = inner.pick_next_task();
    assert_eq!(picked.tid, 14, "the requeued task was not picked");
    assert!(matches!(picked.sched_class(), SchedClass::Rt { .. }),
        "task was not requeued into the RT tree");
}

/// A task queued nowhere (blocked, or currently running) only gets its class
/// updated — Linux's `ctx->queued` idempotence. It must NOT be enqueued.
#[test]
fn set_class_on_unqueued_task_does_not_enqueue_it() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(15);
    assert!(!t.on_rq.load(Ordering::Acquire));

    set_class_with(&|c| cpus.get(c), &t, SchedClass::Rt { prio: 10, policy: SchedPolicy::Fifo });

    assert_eq!(cpus.trees_holding(15), 0, "an unqueued task was enqueued by a class change");
    assert!(matches!(t.sched_class(), SchedClass::Rt { prio: 10, .. }));
    assert!(!t.on_rq.load(Ordering::Acquire));
}

/// Changing to Idle removes the task from the runqueues (idle never queues).
#[test]
fn set_class_to_idle_leaves_no_tree_holding_it() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(16);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    set_class_with(&|c| cpus.get(c), &t, SchedClass::Idle);

    assert_eq!(cpus.trees_holding(16), 0, "idle task must not sit on a class tree");
}

#[test]
fn dequeue_from_owning_rq_reports_the_right_cpu() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(17);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    let (got, cpu) = dequeue_from_owning_rq_with(&|c| cpus.get(c), 17).expect("task located");
    assert_eq!(got.tid, 17);
    assert_eq!(cpu, REMOTE_CPU, "located the wrong runqueue");
    assert!(!got.on_rq.load(Ordering::Acquire), "remove must clear on_rq");
    assert_eq!(cpus.trees_holding(17), 0);
}

#[test]
fn dequeue_from_owning_rq_is_none_when_unqueued() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    assert!(dequeue_from_owning_rq_with(&|c| cpus.get(c), 999).is_none());
}

/// Reproduces the pre-fix algorithm literally — clear `on_rq`, then enqueue on
/// the CALLER's runqueue without dequeuing from the task's real one — and
/// asserts the probe used by the tests above actually detects the resulting
/// double-enqueue. Without this, a broken probe would make those tests vacuous.
#[test]
fn probe_detects_the_pre_fix_double_enqueue() {
    let cpus = Cpus::new(&[CALLER_CPU, REMOTE_CPU]);
    let t = normal_task(18);
    enqueue_on(&cpus, REMOTE_CPU, t.clone());

    // Pre-fix `set_class` body, verbatim in effect:
    let caller = cpus.get(CALLER_CPU).unwrap();
    let mut inner = caller.inner.lock();
    let was_queued = t.on_rq.load(Ordering::Acquire);
    assert!(was_queued);
    inner.remove(t.tid);                       // finds nothing: wrong rq
    t.on_rq.store(false, Ordering::Release);   // defeats the enqueue guard
    inner.enqueue(t.clone());                  // now in the caller's tree too
    drop(inner);

    assert_eq!(cpus.trees_holding(18), 2,
        "probe failed to observe the same Arc in two runqueue trees");
}

/// `RunqueueInner`'s `on_rq` guard is the thing the pre-fix code defeated;
/// confirm it does reject a second enqueue when `on_rq` is left alone.
#[test]
fn enqueue_guard_rejects_a_second_enqueue_when_on_rq_is_respected() {
    let mut inner = RunqueueInner::new(0, Arc::new(Task::new(900, "idle", SchedClass::Idle)));
    let t = normal_task(19);
    inner.enqueue(t.clone());
    inner.enqueue(t.clone());
    assert_eq!(inner.nr_running(), 1, "on_rq guard failed to block a double-enqueue");
}
