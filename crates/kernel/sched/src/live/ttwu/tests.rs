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
use crate::task::SchedClass;
use alloc::vec::Vec;

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
#[test]
fn wake_of_settled_local_sleeper_enqueues_once() {
    const ME: u32 = 20;
    const OTHER: u32 = 21;
    let cpus = Cpus::new(&[ME, OTHER]);
    let t = settled_sleeper(2001, ME);
    assert!(t.claim_wake());

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), false);

    assert_eq!(cpus.trees_holding(2001), 1, "settled local wake must enqueue exactly once");
    assert!(t.on_rq.load(Ordering::Acquire));
}

/// THE BUG. A `wait4` parent claimed by a child exiting on another CPU is
/// still `on_cpu` on its own. Placement must be deferred to the owner's
/// wake-list (Linux `ttwu_queue_wakelist` under
/// `smp_load_acquire(&p->on_cpu)`), never enqueued into the waker's tree.
#[test]
fn wake_of_task_still_on_cpu_elsewhere_is_deferred_not_enqueued() {
    const ME: u32 = 22;
    const OWNER: u32 = 23;
    let cpus = Cpus::new(&[ME, OWNER]);
    let t = parked_but_still_running(2002, OWNER);
    assert!(t.claim_wake(), "the waker legitimately wins the Sleeping->Runnable claim");

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), false);

    assert_eq!(cpus.trees_holding(2002), 0,
        "an executing task (on_cpu) was enqueued into a runqueue tree");
    let deferred = wake_list_drain(OWNER);
    assert_eq!(deferred.len(), 1, "wake was not deferred to the owner CPU's wake list");
    assert_eq!(deferred[0].tid, 2002);
}

/// Deterministic reproduction of the boot panic. Runs the pre-fix
/// `wake_wait4_parent` body verbatim — claim the wake, then enqueue on the
/// CALLER's runqueue — and then the exact sequence `schedule()` performs:
/// `pick_next_task` followed by the `on_cpu` compare-exchange whose failure is
/// `hal::kassert!(..., "schedule selected task already owned by another CPU")`.
#[test]
fn prefix_local_enqueue_makes_the_next_pick_fail_the_on_cpu_cas() {
    const ME: u32 = 24;
    const OWNER: u32 = 25;
    let cpus = Cpus::new(&[ME, OWNER]);
    let t = parked_but_still_running(2003, OWNER);
    assert!(t.claim_wake());

    // Pre-fix body, in effect: no on_cpu handshake, no select_task_rq.
    let caller = cpus.get(ME).expect("test cpu installed");
    {
        let mut inner = caller.inner.lock();
        inner.enqueue(Arc::clone(&t));
        caller.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    assert_eq!(cpus.trees_holding(2003), 1, "probe failed to see the local enqueue");

    // ... and now the caller CPU schedules.
    let picked = caller.inner.lock().pick_next_task();
    assert_eq!(picked.tid, 2003, "the pre-fix enqueue is what the next pick selects");
    assert!(picked.on_cpu
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err(),
        "the on_cpu CAS must reject a task another CPU still owns — this is the \
         assertion that panics the boot");
}

/// The same setup routed through the real placement path leaves the caller's
/// tree empty, so its next pick is the idle task and the CAS succeeds.
#[test]
fn deferred_wake_leaves_the_next_pick_cas_clean() {
    const ME: u32 = 26;
    const OWNER: u32 = 27;
    let cpus = Cpus::new(&[ME, OWNER]);
    let t = parked_but_still_running(2004, OWNER);
    assert!(t.claim_wake());

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), false);

    let caller = cpus.get(ME).expect("test cpu installed");
    let picked = caller.inner.lock().pick_next_task();
    assert!(matches!(picked.sched_class(), SchedClass::Idle),
        "caller must fall through to idle, not to a task owned by another CPU");
    assert!(picked.on_cpu
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok());
    let _ = wake_list_drain(OWNER);
}

/// A settled sleeper whose selected CPU is remote is also deferred — a waker
/// must never take a peer's rq lock (Linux `ttwu_queue_wakelist`).
#[test]
fn wake_selecting_a_remote_cpu_is_deferred_through_its_wake_list() {
    const ME: u32 = 28;
    const REMOTE: u32 = 29;
    let cpus = Cpus::new(&[ME, REMOTE]);
    let t = settled_sleeper(2005, REMOTE);
    // Pin it to REMOTE so select_task_rq cannot choose the local CPU.
    t.cpus_allowed.store(1u64 << REMOTE, Ordering::Release);
    assert!(t.claim_wake());

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), false);

    assert_eq!(cpus.trees_holding(2005), 0, "a waker enqueued onto a peer's runqueue");
    let deferred = wake_list_drain(REMOTE);
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].tid, 2005);
}

/// `force_defer` (the timer-ISR contract: never touch an rq lock from IF=0)
/// defers even a settled, local wake.
#[test]
fn force_defer_never_takes_the_local_runqueue_lock() {
    const ME: u32 = 30;
    const OTHER: u32 = 31;
    let cpus = Cpus::new(&[ME, OTHER]);
    let t = settled_sleeper(2006, ME);
    assert!(t.claim_wake());

    place_runnable_with(&|c| cpus.get(c), ME, Arc::clone(&t), true);

    assert_eq!(cpus.trees_holding(2006), 0);
    let deferred = wake_list_drain(ME);
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].tid, 2006);
}

/// The wake-list drain re-defers a task that is STILL `on_cpu` when its owner
/// gets round to it, rather than enqueuing it (Linux `sched_ttwu_pending`
/// runs after `finish_task_switch` has cleared `on_cpu`).
#[test]
fn drained_wake_of_a_still_running_task_is_re_deferred() {
    const OWNER: u32 = 32;
    let t = parked_but_still_running(2007, OWNER);
    assert!(t.claim_wake());
    assert!(matches!(t.pending_wake(core::ptr::null_mut()), PendingWake::Defer),
        "a task still executing elsewhere must not be reported ready to enqueue");

    t.on_cpu.store(false, Ordering::Release);
    assert!(matches!(t.pending_wake(core::ptr::null_mut()), PendingWake::Ready),
        "once switched off it becomes enqueueable");
}

/// `select_task_rq_with` honours `cpus_allowed`; a mask that excludes the
/// caller must not resolve to the caller.
#[test]
fn select_task_rq_honours_the_affinity_mask() {
    const ME: u32 = 33;
    const ALLOWED: u32 = 34;
    let cpus = Cpus::new(&[ME, ALLOWED]);
    let t = settled_sleeper(2008, ALLOWED);
    t.cpus_allowed.store(1u64 << ALLOWED, Ordering::Release);

    assert_eq!(select_task_rq_with(&|c| cpus.get(c), ME, &t), ALLOWED);
}
