use core::sync::atomic::Ordering;
use crate::{Task, RunqueueInner};
use crate::live::runqueue::Runqueue;
use crate::sched_enc::wakeup::{cand_of, wakeup_preempt};

// Caller holds the destination runqueue lock, pinning its current task.
pub(super) fn prepare_wake(rq: &Runqueue, inner: &mut RunqueueInner, wakee: &Task, now: u64) {
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() {
        wakee.lift_vruntime(inner.cfs.min_vruntime_for(wakee));
        return;
    }
    // SAFETY: caller holds rq.inner, pinning the current task's strong reference.
    let current = unsafe { &*raw };
    if matches!(current.sched_class(), crate::SchedClass::Normal { .. })
        && matches!(wakee.sched_class(), crate::SchedClass::Normal { .. })
        && now > current.sched.se.exec_start.load(Ordering::Acquire)
    {
        crate::live::schedule::settle_running_for_change(current, inner, now);
    }
    wakee.lift_vruntime(inner.cfs.min_vruntime_for(wakee));
}

// Wakee is enqueued and current accounting is settled under this rq lock.
pub(super) fn wake_preempts(rq: &Runqueue, inner: &RunqueueInner, wakee: &Task) -> bool {
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return true; }
    // SAFETY: caller holds rq.inner, pinning the current task's strong reference.
    let current = unsafe { &*raw };
    let wake = cand_of(wakee);
    let curr = cand_of(current);
    if wake.rank == crate::sched_enc::wakeup::RANK_FAIR && curr.rank == wake.rank {
        let idle = crate::sched_enc::SCHED_IDLE;
        if (wake.policy == idle) != (curr.policy == idle) { return curr.policy == idle; }
        if wake.policy != crate::sched_enc::SCHED_NORMAL { return false; }
        return inner.cfs.wakeup_preempts(current, wakee);
    }
    wakeup_preempt(wake, curr)
}

#[cfg(test)]
#[path = "tests/preempt.rs"]
mod tests;
