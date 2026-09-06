// Deterministic two-CPU model for the ttwu placement invariant:
//
//   A task with `on_cpu` set is EXECUTING on its owner CPU. It must never be
//   enqueued into any runqueue's class tree — not even by a waker that
//   legitimately won the Sleeping->Runnable claim, because the task sets itself
//   Sleeping BEFORE `schedule()` finishes switching it off, so "claimed the
//   wake" and "stopped running" are two different instants.
//
// Violating it is the `schedule()` panic "selected task already owned by
// another CPU" — reproduced literally in
// `prefix_local_enqueue_makes_the_next_pick_fail_the_on_cpu_cas` below, which
// runs the exact CAS from `live::schedule::switch`.
//
// Real `Runqueue`s are built locally rather than installed into `GLOBALS`:
// that array only accepts writes for `this_cpu()` (unconditionally 0 hosted)
// and is process-global, so parallel `cargo test` threads would collide. The
// accessor closure supplies the CPU->rq mapping, exactly as `global_for` does
// in production (same split as `live::rq_locate`).
//
// `WAKE_LISTS` IS a process-global static, so every test here uses its own
// pair of CPU ids and never touches another test's slots.

use super::*;
use crate::TaskState;
use crate::task::{SchedClass, SchedPolicy};
use crate::sched_enc::{SCHED_BATCH, SCHED_IDLE, SCHED_NORMAL};
use alloc::vec::Vec;

mod current;
mod accounting;

/// Two installed runqueues, indexed by CPU id.
struct Cpus {
    rqs: Vec<(u32, Runqueue)>,
}

impl Cpus {
    fn new(cpus: &[u32]) -> Self {
        let rqs = cpus.iter().map(|&c| {
            (c, Runqueue::new(c as u16, Arc::new(Task::new(0xF000 + c, "idle", SchedClass::Idle))))
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

/// A task parked in a blocking wait on `owner`, whose `schedule()` has not yet
/// completed: state Sleeping, `on_cpu` still set, queued nowhere. This is the
/// exact state a `wait4` parent is in between `park_for_wait4` and the
/// incoming task's `finish_task_switch`.
fn parked_but_still_running(tid: u32, owner: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "waiter", SchedClass::Normal { weight: 1024 }));
    t.cpu.store(owner as u16, Ordering::Release);
    t.on_cpu.store(true, Ordering::Release);
    t.set_state(TaskState::Sleeping);
    t
}

/// A task that has fully stopped running and is parked on a wait list.
fn settled_sleeper(tid: u32, owner: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "waiter", SchedClass::Normal { weight: 1024 }));
    t.cpu.store(owner as u16, Ordering::Release);
    t.on_cpu.store(false, Ordering::Release);
    t.set_state(TaskState::Sleeping);
    t
}

/// Baseline: a settled sleeper woken on its own CPU goes straight into that
/// CPU's tree, in exactly one tree.
// ---- wakeup preemption (`wakeup_preempt` applied at the enqueue) ----
//
// A wake places a task; whether it also TAKES the CPU is a separate question,
// and answering it "always yes" is what made SCHED_FIFO, SCHED_BATCH and
// SCHED_IDLE behave identically to SCHED_NORMAL. These drive the real
// `place_runnable_with` and read the reschedule request it left behind.

/// Install `t` as CPU `cpu`'s running task and clear any pending request, so
/// the assertion afterwards can only observe what the wake itself asked for.
fn make_current(rq: &Runqueue, t: &Arc<Task>, cpu: u32) {
    // SAFETY: hosted model runqueue owned by this test; no switch is in flight.
    let _ = unsafe { rq.swap_current(Arc::clone(t)) };
    t.on_cpu.store(true, Ordering::Release);
    t.cpu.store(cpu as u16, Ordering::Release);
    let _ = crate::preempt::resched::clear_tsk_need_resched(t);
}

fn fifo_task(tid: u32, prio: u8) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "rt", SchedClass::Rt { prio, policy: SchedPolicy::Fifo }));
    t
}

fn fair_task(tid: u32, policy: u32, vruntime: u64) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "fair", SchedClass::Normal { weight: 1024 }));
    t.set_normal_sched_class_policy(SchedClass::Normal {
        weight: if policy == SCHED_IDLE { 3 } else { 1024 },
    }, policy);
    t.sched.se.vruntime.store(vruntime, Ordering::Release);
    t
}

/// Wake `wakee` on CPU `cpu` where `curr` is running; report whether the wake
/// asked that CPU to reschedule.
///
/// The request is read from the per-CPU anchor rather than from `curr`:
/// `resched_curr` routes through the process-global runqueue array, which a
/// hosted test cannot install into, so it lands on the anchor for `cpu`. Every
/// caller therefore passes a CPU id no other test uses, and the anchor starts
/// clear.
fn wake_asks_for_resched(cpu: u32, curr: &Arc<Task>, wakee: Arc<Task>) -> bool {
    let cpus = Cpus::new(&[cpu]);
    let rq = cpus.get(cpu).expect("just installed");
    make_current(rq, curr, cpu);
    wakee.cpu.store(cpu as u16, Ordering::Release);
    wakee.on_cpu.store(false, Ordering::Release);
    wakee.set_state(TaskState::Sleeping);
    assert!(wakee.claim_wake());
    assert!(!crate::preempt::need_resched_on(cpu as usize), "anchor must start clear");
    place_runnable_with(&|c| cpus.get(c), cpu, wakee, false);
    crate::preempt::need_resched_on(cpu as usize)
}

/// THE FIFO GUARANTEE. A running SCHED_FIFO task keeps the CPU when a peer
/// wakes at its own priority; only a strictly higher priority takes it away.
#[path = "placement_tests.rs"]
mod placement_tests;

#[path = "preemption_tests.rs"]
mod preemption_tests;
