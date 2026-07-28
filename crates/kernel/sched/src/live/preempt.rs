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
/// must NOT preempt unconditionally: `task_tick_rt` (`kernel/sched/rt.c`)
/// returns immediately for `SCHED_FIFO`, because a FIFO task runs until it
/// blocks or yields — that is its defining guarantee, and preempting it every
/// tick makes FIFO behave exactly like RR.
///
/// `SCHED_RR` decrements its quantum and only requeues when it is exhausted,
/// and then only if it is not alone at its level (Linux checks
/// `run_list.prev != run_list.next`; requeueing a sole runnable task is pure
/// overhead). Everything else — fair and idle — preempts per tick as before.
/// # C: O(1)
pub fn task_tick() {
    let Some(cur) = crate::current() else { crate::preempt::set_need_resched(); return; };
    let policy = cur.policy.load(core::sync::atomic::Ordering::Acquire);
    let left = cur.rt_time_slice.load(core::sync::atomic::Ordering::Acquire);
    if policy == crate::sched_enc::SCHED_RR {
        if left > 1 {
            cur.rt_time_slice.store(left - 1, core::sync::atomic::Ordering::Release);
            return;
        }
        cur.rt_time_slice.store(crate::sched_enc::RR_TIMESLICE_TICKS, core::sync::atomic::Ordering::Release);
    }
    let peer = crate::live::runqueue::has_rt_peer_at_same_level(cur);
    if crate::sched_enc::rt_tick_wants_resched(policy, left, peer) {
        crate::preempt::set_need_resched();
    }
}
