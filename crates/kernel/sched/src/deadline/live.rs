// Live wiring of the deadline class: the points where a running task's budget
// is charged, where an exhausted budget throws it off the ready set, and where
// the replenishment timer puts it back.
//
// Every decision here is delegated to the pure rules in `cbs.rs`; this file
// only snapshots the entity, applies the answer and touches the runqueue. That
// split is what keeps the throttle/replenish edges reachable from `cargo test`
// while the parts that need a runqueue stay thin.

use alloc::sync::Arc;

use super::cbs::{self, Charged, DlSched};
use super::clock::now_ns;
use super::replenish;
use crate::task::{SchedClass, Task};

/// Stamp the start of a stint on-CPU. The charge measures from here, so a task
/// that runs for a fraction of a tick is charged for the fraction.
/// # C: O(1)
pub fn set_next_task_dl(t: &Task, now: u64) {
    if !matches!(t.sched_class(), SchedClass::Deadline) { return; }
    t.dl.set_exec_start(now);
}

/// Charge the time `t` just ran against its current instance and report
/// whether the instance is now over.
///
/// This is the single accounting point: the periodic tick and the schedule-out
/// path both call it, and the elapsed-time stamp is consumed by whichever gets
/// there first, so the same nanosecond is never charged twice.
/// # C: O(1)
pub fn update_curr_dl(t: &Task, now: u64) -> Charged {
    if !matches!(t.sched_class(), SchedClass::Deadline) { return Charged::Running; }
    let p = t.dl.params();
    let mut s = t.dl.sched();
    let delta = t.dl.take_delta(now);
    if delta != 0 { crate::cputime::charge_exec_runtime(t, delta); }
    let out = cbs::charge(&p, &mut s, delta);
    t.dl.store_sched(&s);
    out
}

/// The periodic tick's deadline-class hook. A task whose budget ran out must
/// leave the CPU at once — waiting for its next voluntary schedule would let it
/// consume bandwidth it was never admitted for.
/// # C: O(1)
pub fn task_tick_dl(t: &Task) {
    if update_curr_dl(t, now_ns()) == Charged::Throttle { crate::preempt::set_need_resched(); }
}

/// `sched_yield` on a deadline task: give up the REMAINDER OF THE INSTANCE,
/// not merely the CPU. The budget left in this period is donated, and the task
/// returns at the start of the next one with a full grant and a deadline one
/// period later.
///
/// Yielding only the CPU would be meaningless for a class picked by deadline —
/// the task would be re-picked immediately, since its deadline is unchanged and
/// it is still the earliest.
/// # C: O(1)
pub fn yield_dl(t: &Task) {
    t.dl.set_yielded();
    let _ = update_curr_dl(t, now_ns());
}

/// Deadline-class rule for a task ENTERING the ready set from a wakeup.
///
/// Returns `false` when the task must not be queued yet — its budget is spent
/// and it owes the wait until its next period. The caller has the `Arc`, so the
/// replenishment is armed here rather than left to a later sweep to discover.
/// # C: O(log N)
pub fn on_wakeup_enqueue(t: &Arc<Task>) -> bool {
    if !matches!(t.sched_class(), SchedClass::Deadline) { return true; }
    let now = now_ns();
    let p = t.dl.params();
    let mut s = t.dl.sched();
    if s.throttled {
        t.dl.store_sched(&s);
        return arm_replenish(t, &p, &s);
    }
    cbs::update_dl_entity(&p, &mut s, now);
    let constrained = cbs::check_constrained(&p, &mut s, now);
    t.dl.store_sched(&s);
    if constrained { return arm_replenish(t, &p, &s); }
    true
}

/// Deadline-class rule for a task RE-ENTERING the ready set from a preemption
/// (`put_prev_task`). Its instance is untouched — a preempted task did not give
/// anything up — but a task thrown off by an exhausted budget stays off.
/// # C: O(log N)
pub fn on_requeue(t: &Arc<Task>) -> bool {
    if !matches!(t.sched_class(), SchedClass::Deadline) { return true; }
    if !t.dl.is_throttled() { return true; }
    let p = t.dl.params();
    let s = t.dl.sched();
    arm_replenish(t, &p, &s)
}

/// Park a throttled entity until its next instance begins, and report whether
/// it may enter the ready set NOW.
///
/// When the replenishment instant has already passed the entity is replenished
/// inline and admitted at once: arming a timer for the past would leave it off
/// the ready set forever, waiting for an event that can no longer happen.
/// # C: O(log N)
fn arm_replenish(t: &Arc<Task>, p: &super::params::DlParams, s: &DlSched) -> bool {
    let now = now_ns();
    let at = cbs::dl_next_period(p, s);
    if !cbs::dl_time_before(now, at) {
        let mut s2 = *s;
        cbs::replenish(p, &mut s2, now);
        t.dl.store_sched(&s2);
        replenish::disarm(t);
        return true;
    }
    replenish::arm(t, at);
    false
}

/// Replenish every throttled entity whose instant has arrived and return them
/// to the ready set — the deadline class's bandwidth timer.
///
/// Runs from the timer interrupt, which is also what programs the one-shot for
/// this queue's earliest instant, so a throttle ends at the start of the period
/// rather than at the next accounting tick.
/// # C: O(due · log N)
/// # Ctx: timer IRQ
pub fn expire_throttled(now: u64) {
    let due = replenish::take_due(now);
    if due.is_empty() { return; }
    for t in due {
        let p = t.dl.params();
        let mut s = t.dl.sched();
        cbs::replenish(&p, &mut s, now);
        t.dl.store_sched(&s);
        t.dl.set_replenish_at(0);
        // A task that was sleeping when its budget ran out is replenished but
        // not queued: it re-enters the ready set through its own wakeup, which
        // then sees an un-throttled entity.
        if t.state() != crate::task::TaskState::Runnable { continue; }
        requeue_replenished(t);
    }
}

/// [`expire_throttled`] against the current monotonic time — the timer
/// dispatcher's entry point.
/// # C: O(due · log N)
/// # Ctx: timer IRQ
pub fn expire_throttled_now() { expire_throttled(now_ns()); }

/// Commit a validated reservation onto `t` and start its first instance now.
/// # C: O(1)
pub fn enter_class(t: &Task, p: &super::params::DlParams) {
    let now = now_ns();
    t.dl.set_params(p);
    let mut s = DlSched::default();
    cbs::replenish_new_period(p, &mut s, now);
    t.dl.store_sched(&s);
    t.dl.set_exec_start(now);
    t.dl.set_replenish_at(0);
}

/// Re-arm an already-deadline task onto changed parameters. The instance is
/// re-derived so a task cannot mint budget by re-issuing its own parameters
/// mid-period.
/// # C: O(1)
pub fn reset_params(t: &Task, p: &super::params::DlParams) {
    let now = now_ns();
    t.dl.set_params(p);
    let mut s = t.dl.sched();
    s.throttled = false;
    s.yielded = false;
    cbs::replenish_new_period(p, &mut s, now);
    t.dl.store_sched(&s);
}

/// Drop `t`'s reservation and release its admitted bandwidth. Run when a task
/// leaves the deadline class or exits — the ledger must not keep a booking for
/// an entity that no longer contends.
/// # C: O(N throttled)
pub fn leave_class(t: &Task) {
    let bw = t.dl.bw();
    if bw != 0 { super::bw::DL_BW.release(bw); }
    replenish::disarm(t);
    t.dl.clear();
}

/// Would `mask` confine a deadline task to fewer CPUs than the span its
/// reservation was admitted against? The one predicate both the affinity
/// syscall and the cpuset writer consult, so the two cannot disagree about
/// what a reservation was booked over.
/// # C: O(1)
pub fn confined_below_span(t: &Task, mask: u64) -> bool {
    matches!(t.sched_class(), SchedClass::Deadline) && super::span() & !mask != 0
}

/// Return a replenished entity to the ready set through the DEFERRED wake path.
///
/// Never the runqueue lock directly: this runs in the hard timer interrupt, and
/// that lock is taken plain by process context. Spinning on it from the
/// interrupt self-deadlocks the CPU (`06§3.1`). The deferred path pushes to the
/// target's lock-free wake list and asks it to reschedule, which is the same
/// route every other interrupt-context wake takes.
///
/// Selected at the module boundary because a build without the live scheduler
/// has no runqueue to return it to (`07§5`).
/// # C: O(N_cpus)
/// # Ctx: timer IRQ
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn requeue_replenished(t: Arc<Task>) {
    // SAFETY: replenishment site; `t` is Runnable, on no runqueue (the throttle
    // took it off) and not executing, and this owns an `Arc` for the placement.
    unsafe { crate::live::ttwu::place_runnable(t, true); }
}

/// # C: O(1)
#[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
fn requeue_replenished(_t: Arc<Task>) {}
