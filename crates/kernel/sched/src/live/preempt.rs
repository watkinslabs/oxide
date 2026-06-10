// Need-resched flag forwarders per `13§9`.
//
// One switch engine (`schedule()`): the timer/IPI IRQ path only sets
// `need_resched`; the actual switch happens at the return-to-user slow
// path (`oxide_irq_resched_on_exit` → `schedule()`), at `preempt_enable`
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
