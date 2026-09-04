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

#[cfg(test)]
type RaceGate = (usize, std::sync::mpsc::Sender<()>,
    Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
#[cfg(test)]
static LEAVE_CLAIM_GATE: std::sync::Mutex<Option<RaceGate>> = std::sync::Mutex::new(None);
#[cfg(test)]
static RESET_GATE: std::sync::Mutex<Option<RaceGate>> = std::sync::Mutex::new(None);

/// Install the deterministic leave-race gate. Hosted tests only.
/// # C: O(1)
#[cfg(test)]
pub(super) fn set_leave_claim_gate(gate: Option<(&Task, std::sync::mpsc::Sender<()>,
    Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>)>) {
    let gate = gate.map(|(t, entered, release)|
        (t as *const Task as usize, entered, release));
    *LEAVE_CLAIM_GATE.lock().unwrap_or_else(|e| e.into_inner()) = gate;
}

/// Install the deterministic parameter-reset gate. Hosted tests only.
/// # C: O(1)
#[cfg(test)]
pub(super) fn set_reset_gate(gate: Option<(&Task, std::sync::mpsc::Sender<()>,
    Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>)>) {
    let gate = gate.map(|(t, entered, release)|
        (t as *const Task as usize, entered, release));
    *RESET_GATE.lock().unwrap_or_else(|e| e.into_inner()) = gate;
}

#[cfg(test)]
fn race_gate_wait(slot: &std::sync::Mutex<Option<RaceGate>>, t: &Task) {
    let gate = slot.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some((task, entered, release)) = gate {
        if task == t as *const Task as usize {
            entered.send(()).expect("deadline race observer disappeared");
            let (lock, cv) = &*release;
            let released = lock.lock().unwrap_or_else(|e| e.into_inner());
            let (released, timeout) = cv.wait_timeout_while(released,
                std::time::Duration::from_secs(2), |released| !*released)
                .unwrap_or_else(|e| e.into_inner());
            assert!(*released && !timeout.timed_out(), "deadline race release timed out");
        }
    }
}

/// Stamp the start of a stint on-CPU. The charge measures from here, so a task
/// that runs for a fraction of a tick is charged for the fraction.
/// # C: O(1)
pub(crate) fn set_next_task_dl(t: &Task, now: u64) {
    if !matches!(t.sched_class(), SchedClass::Deadline) { return; }
    t.sched.dl.set_exec_start(now);
}

/// Charge the time `t` just ran against its current instance and report
/// whether the instance is now over.
///
/// This is the single accounting point: the periodic tick and the schedule-out
/// path both call it, and the elapsed-time stamp is consumed by whichever gets
/// there first, so the same nanosecond is never charged twice.
/// # C: O(1)
pub(crate) fn update_curr_dl(t: &Task, now: u64) -> Charged {
    if !matches!(t.sched_class(), SchedClass::Deadline) { return Charged::Running; }
    let p = t.effective_dl_params();
    let mut s = t.sched.dl.sched();
    let delta = t.sched.dl.take_delta(now);
    if delta != 0 { crate::cputime::charge_exec_runtime(t, delta); }
    let out = cbs::charge(&p, &mut s, delta);
    if out == Charged::Throttle && t.uses_borrowed_dl() {
        replenish_pi_state(t, &p, &mut s, now);
    }
    t.sched.dl.store_sched(&s);
    out
}

/// The periodic tick's deadline-class hook. A task whose budget ran out must
/// leave the CPU at once — waiting for its next voluntary schedule would let it
/// consume bandwidth it was never admitted for.
/// # C: O(1)
pub(crate) fn task_tick_dl(t: &Task) {
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
pub(crate) fn yield_dl(t: &Task) {
    t.sched.dl.set_yielded();
    let _ = update_curr_dl(t, now_ns());
}

/// Deadline-class rule for a task ENTERING the ready set from a wakeup.
///
/// Returns `false` when the task must not be queued yet — its budget is spent
/// and it owes the wait until its next period. The caller has the `Arc`, so the
/// replenishment is armed here rather than left to a later sweep to discover.
/// # C: O(log N)
pub(crate) fn on_wakeup_enqueue(t: &Arc<Task>) -> bool {
    if !matches!(t.sched_class(), SchedClass::Deadline) { return true; }
    let now = now_ns();
    let p = t.effective_dl_params();
    let mut s = t.sched.dl.sched();
    if t.uses_borrowed_dl() {
        if s.throttled { replenish_pi(t, now); }
        else if cbs::dl_time_before(s.deadline, now)
            || cbs::dl_entity_overflow(&p, &s, now) {
            cbs::replenish_new_period(&p, &mut s, now);
            t.sched.dl.store_sched(&s);
        }
        return true;
    }
    if s.throttled {
        t.sched.dl.store_sched(&s);
        return arm_replenish(t, &p, &s);
    }
    cbs::update_dl_entity(&p, &mut s, now);
    let constrained = cbs::check_constrained(&p, &mut s, now);
    t.sched.dl.store_sched(&s);
    if constrained { return arm_replenish(t, &p, &s); }
    true
}

/// Deadline-class rule for a task RE-ENTERING the ready set from a preemption
/// (`put_prev_task`). Its instance is untouched — a preempted task did not give
/// anything up — but a task thrown off by an exhausted budget stays off.
/// # C: O(log N)
pub(crate) fn on_requeue(t: &Arc<Task>) -> bool {
    if !matches!(t.sched_class(), SchedClass::Deadline) { return true; }
    if !t.sched.dl.is_throttled() { return true; }
    if t.uses_borrowed_dl() {
        replenish_pi(t, now_ns());
        return true;
    }
    let p = t.effective_dl_params();
    let s = t.sched.dl.sched();
    arm_replenish(t, &p, &s)
}

/// Apply inherited parameters to the owner's CBS entity and override stale throttle. # C: O(N)
pub(crate) fn replenish_pi(t: &Task, now: u64) {
    if !t.uses_borrowed_dl() { return; }
    replenish::disarm(t);
    let p = t.effective_dl_params();
    let mut s = t.sched.dl.sched();
    replenish_pi_state(t, &p, &mut s, now);
    t.sched.dl.store_sched(&s);
}

fn replenish_pi_state(t: &Task, p: &super::params::DlParams, s: &mut DlSched, now: u64) {
    if p.is_special() {
        s.throttled = false;
        s.yielded = false;
        return;
    }
    if matches!(t.normal_sched_class(), SchedClass::Deadline) { cbs::replenish(p, s, now); }
    else {
        cbs::replenish_new_period(p, s, now);
        s.throttled = false;
        s.yielded = false;
    }
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
        t.sched.dl.store_sched(&s2);
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
    super::inactive::expire(now);
    while let Some(due) = replenish::take_due(now) {
        #[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
        {
            let _ = replenish_claimed(&due, now);
            continue;
        }
        #[cfg(test)]
        if crate::live::runqueue::global().is_none() {
            replenish_claimed(&due, now);
            continue;
        }
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        let get_rq = |cpu| unsafe { crate::live::runqueue::global_for(cpu) };
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        match crate::live::rq_locate::task_rq_lock_with(&get_rq, &due.task) {
            crate::live::rq_locate::StableTaskGuard::Owned(mut lock) => {
                if !replenish_claimed(&due, now) { continue; }
                if due.task.state() == crate::task::TaskState::Runnable
                    && !due.task.on_class_rq.load(core::sync::atomic::Ordering::Acquire)
                    && !lock.is_current_donor(&due.task) {
                    lock.inner_mut().restore_sched_change(Arc::clone(&due.task),
                        crate::sched_enc::requeue::RequeuePos::Head);
                    lock.publish_nr_running();
                }
            }
            crate::live::rq_locate::StableTaskGuard::OffRq(_pi) => {
                let _ = replenish_claimed(&due, now);
            }
        }
    }
}

pub(super) fn replenish_claimed(due: &replenish::DueReplenishment, now: u64) -> bool {
    if !due.claim.current()
        || due.task.sched.dl.replenish_at() != due.claim.at()
        || !matches!(due.task.sched_class(), SchedClass::Deadline)
        || due.task.uses_borrowed_dl()
        || !due.task.sched.dl.is_throttled() {
        if due.claim.current() { let _ = due.claim.finish(); }
        return false;
    }
    let p = due.task.effective_dl_params();
    let mut s = due.task.sched.dl.sched();
    cbs::replenish(&p, &mut s, now);
    due.task.sched.dl.store_sched(&s);
    due.claim.finish()
}

/// [`expire_throttled`] against the current monotonic time — the timer
/// dispatcher's entry point.
/// # C: O(due · log N)
/// # Ctx: timer IRQ
pub fn expire_throttled_now() { expire_throttled(now_ns()); }

/// Commit a validated reservation onto `t` and start its first instance now.
/// # C: O(1)
pub(crate) fn enter_class(t: &Task, p: &super::params::DlParams) {
    if terminal_admission(t, p) { return; }
    let now = now_ns();
    if t.sched.dl.take_resume_inactive() {
        t.sched.dl.set_params(p);
        replenish::disarm(t);
        t.sched.dl.set_exec_start(now);
        t.sched.dl.set_replenish_at(0);
        return;
    }
    let mut s = DlSched::default();
    cbs::replenish_new_period(p, &mut s, now);
    t.sched.dl.store_entity(p, &s);
    t.sched.dl.set_exec_start(now);
    t.sched.dl.set_replenish_at(0);
}

/// Replace static parameters of an already-deadline task. The live CBS
/// runtime/deadline instance survives exactly; replenishment owns its reset.
/// # C: O(1)
pub(crate) fn reset_params(t: &Task, p: &super::params::DlParams) {
    if terminal_admission(t, p) { return; }
    let _ = t.sched.dl.take_resume_inactive();
    #[cfg(test)]
    race_gate_wait(&RESET_GATE, t);
    t.sched.dl.set_params(p);
}

fn terminal_admission(t: &Task, p: &super::params::DlParams) -> bool {
    if !matches!(t.state(), crate::TaskState::Zombie) { return false; }
    // Admission commits before entity parameters. If exit won TaskPi, return
    // that just-committed booking instead of resurrecting a terminal task.
    if !p.is_special() && p.bw != 0 { super::bw::DL_BW.release(p.bw); }
    replenish::disarm(t);
    t.sched.dl.clear();
    true
}

/// Retain an ordinary reservation until its zero-lag instant after class leave
/// or exit. Special entities have no booking and clear immediately.
/// # C: O(N throttled + log N inactive)
pub(crate) fn leave_class(t: &Task) {
    leave_class_for(t, true);
}

/// Leave an ordinary generation while another deadline-special generation is
/// installed on the same entity. The old booking expires, but must not clear
/// the new special parameters when its timer fires. # C: O(N + log N)
pub(crate) fn leave_for_special(t: &Task) { leave_class_for(t, false); }

fn leave_class_for(t: &Task, clear_on_expire: bool) {
    replenish::disarm(t);
    let (p, s) = t.sched.dl.snapshot();
    if p.bw == 0 || p.is_special() {
        t.sched.dl.clear();
        return;
    }
    if t.sched.dl.has_inactive() { return; }
    let at = super::inactive::zero_lag(&p, &s);
    let now = now_ns();
    if cbs::dl_time_before(now, at)
        && super::inactive::arm(t, at, p.bw, clear_on_expire) { return; }
    let bw = t.sched.dl.take_bw();
    #[cfg(test)]
    race_gate_wait(&LEAVE_CLAIM_GATE, t);
    if bw != 0 { super::bw::DL_BW.release(bw); }
    t.sched.dl.clear();
}

/// Would `mask` confine a deadline task to fewer CPUs than the span its
/// reservation was admitted against? The one predicate both the affinity
/// syscall and the cpuset writer consult, so the two cannot disagree about
/// what a reservation was booked over.
/// # C: O(1)
pub fn confined_below_span(t: &Task, mask: cpu::CpuMask) -> bool {
    matches!(t.sched_class(), SchedClass::Deadline) && !super::span().is_subset_of(mask)
}
