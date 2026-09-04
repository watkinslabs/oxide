// Need-resched flag forwarders per `13§9`.
//
// One switch engine (`schedule()`): the timer/IPI IRQ path only sets
// `need_resched`; the actual switch happens at the return-to-user slow
// path (`oxide_irq_exit_to_user` → the return-to-user work loop), at `preempt_enable`
// drop-to-zero, and at voluntary yields. There is no IRQ-tail staging
// (`stage_switch`/`tick_pick_next`/`schedule_from_irq` were collapsed into
// the one engine per `sched-anal.md`/`smp-arch.md` Phase A).
//
// `NEED_RESCHED` lives in `crate::preempt` (per-CPU) so the preempt-enable
// check and the IRQ-exit check share one flag. These shims just forward.

/// Set need-resched. Called from timer tick + wakeup paths.
/// # C: O(1)
pub fn set_need_resched() { crate::preempt::set_need_resched() }

/// Clear need-resched + report prior. Used by the cooperative
/// `tick_yield()`.
/// # C: O(1)
pub fn clear_need_resched() -> bool { crate::preempt::take_need_resched() }

/// Reads + clears the shared `NEED_RESCHED` flag. Forwards to
/// `crate::preempt::take_need_resched`.
/// # C: O(1)
pub fn need_resched() -> bool { crate::preempt::take_need_resched() }

/// Linux `scheduler_tick` → `curr->sched_class->task_tick`. The periodic tick
/// must NOT preempt unconditionally: `task_tick_rt`
/// returns immediately for `SCHED_FIFO`, because a FIFO task runs until it
/// blocks or yields — that is its defining guarantee, and preempting it every
/// tick makes FIFO behave exactly like RR.
///
/// Runtime is settled before the class decision, including the FIFO early
/// return. `SCHED_RR` decrements its quantum and only requeues when it is
/// exhausted, and then only if it is not alone at its level. Everything else
/// — fair and idle — preempts per tick as before.
/// # C: O(1)
pub fn task_tick() {
    let Some(rq) = crate::live::runqueue::global()
        else { crate::preempt::set_need_resched(); return; };
    // SAFETY: timer IRQ context is preempt-disabled and this CPU's runqueue
    // owns its current task for the complete tick callback.
    let cur = unsafe { rq.current_ref() };
    // Deadline class first: it is the only class whose tick can REVOKE the CPU
    // outright, and its budget must be charged before any other class rule runs.
    if matches!(cur.sched_class(), crate::SchedClass::Deadline) {
        crate::deadline::live::task_tick_dl(cur);
        return;
    }
    task_tick_with_clock(cur, rq, crate::live::schedule::change_clock_now);
}

fn task_tick_with_clock<F>(cur: &crate::Task, rq: &crate::live::runqueue::Runqueue, now: F)
where F: FnOnce() -> u64 {
    use core::sync::atomic::Ordering;

    // The rq lock serialises this snapshot with class changes and keeps the
    // running Fair entity outside its class tree while its vruntime advances.
    let inner = rq.inner.lock_irqsave::<crate::live::runqueue::RqIrq>();
    crate::live::schedule::settle_running_for_change(cur, &inner, now());
    let policy = cur.sched_policy_code();
    if policy == crate::sched_enc::SCHED_FIFO { return; }
    if policy != crate::sched_enc::SCHED_RR {
        crate::preempt::set_need_resched();
        return;
    }
    let left = cur.sched.rt.time_slice.load(Ordering::Acquire);
    if left > 1 {
        cur.sched.rt.time_slice.store(left - 1, Ordering::Release);
        return;
    }
    cur.sched.rt.time_slice.store(crate::sched_enc::RR_TIMESLICE_TICKS,
                                  Ordering::Release);
    let peer = match cur.sched_class() {
        crate::SchedClass::Rt { prio, .. } => inner.rt.has_peer_at(prio),
        _ => false,
    };
    // A spent SCHED_RR quantum is the one tick outcome that ROTATES the task:
    // mark it so `put_prev_task` returns it behind its equal-priority peers
    // instead of ahead of them. Nothing else — a SCHED_FIFO task has no
    // quantum and must keep its place across any number of preemptions.
    if crate::sched_enc::requeue::tick_gives_up_turn(policy, left, peer) {
        cur.rt_requeue_tail.store(true, Ordering::Release);
    }
    if crate::sched_enc::rt_tick_wants_resched(policy, left, peer) {
        crate::preempt::set_need_resched();
    }
}

#[cfg(test)]
#[path = "preempt/tests.rs"]
mod tests;
