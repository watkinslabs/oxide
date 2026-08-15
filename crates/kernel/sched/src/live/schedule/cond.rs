//! Conditional process-context rescheduling.

use crate::preempt;

fn may_resched(count: u32, in_atomic: bool, irqs_disabled: bool, pending: bool,
               runqueue_active: bool) -> bool {
    count == 0 && !in_atomic && !irqs_disabled && pending && runqueue_active
}

/// Yield only when a reschedule is pending and the caller is in a sleepable
/// process-context safe point.  Unlike an explicit yield, this neither forces
/// a switch nor opens an idle window after the scheduler returns.
/// # C: O(log N) only when a reschedule is pending
pub fn cond_resched() -> bool {
    if !may_resched(preempt::preempt_count(), preempt::in_atomic(), preempt::irqs_disabled(),
        preempt::need_resched(), super::lifecycle::runqueue_active())
    {
        return false;
    }
    // SAFETY: the gate above proves process context, IRQs enabled, no
    // preempt/BH/IRQ nesting, a live runqueue, and a pending reschedule.
    unsafe { super::switch::schedule(); }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reschedule_requires_a_process_context_safe_point() {
        assert!(may_resched(0, false, false, true, true));
        assert!(!may_resched(0, true, false, true, true));
        assert!(!may_resched(0, false, true, true, true));
        assert!(!may_resched(preempt::PREEMPT_DISABLED, false, false, true, true));
        assert!(!may_resched(0, false, false, false, true));
        assert!(!may_resched(0, false, false, true, false));
    }
}
