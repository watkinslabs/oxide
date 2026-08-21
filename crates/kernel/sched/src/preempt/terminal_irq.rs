//! Terminal CPU-hotplug transfer of hardirq accounting.

use super::{HARDIRQ_OFFSET, irq_enter, irq_exit, preempt_count};

/// One dispatcher hardirq credit retired before a non-returning CPU-down.
/// Dropping restores the credit when firmware or admission refuses teardown.
pub struct TerminalIrqExit { restore: bool }

impl TerminalIrqExit {
    /// Whether the current dispatcher owns exactly one terminal hardirq credit.
    /// # C: O(1)
    pub fn admitted() -> bool { preempt_count() == HARDIRQ_OFFSET }

    /// Retire one otherwise-terminal IRQ dispatch. Refuses non-IRQ, nested,
    /// or lock-bearing contexts rather than normalizing unrelated imbalance.
    /// # C: O(1)
    /// # Ctx: hardirq, IRQs masked
    pub fn begin() -> Option<Self> {
        if !Self::admitted() { return None; }
        irq_exit(); Some(Self { restore: true })
    }

    /// Commit a CPU-down that cannot return through the dispatcher tail.
    /// # C: O(1)
    /// # Ctx: hardirq terminal path, IRQs masked
    pub fn commit(mut self) { self.restore = false; }
}

impl Drop for TerminalIrqExit {
    fn drop(&mut self) { if self.restore { irq_enter(); } }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_restores_outer_dispatch_ownership() {
        crate::preempt::_test_reset(); irq_enter();
        let exit = TerminalIrqExit::begin().unwrap();
        assert_eq!(preempt_count(), 0);
        drop(exit);
        assert_eq!(preempt_count(), HARDIRQ_OFFSET);
        irq_exit(); assert_eq!(preempt_count(), 0);
    }

    #[test]
    fn committed_terminal_exit_leaves_no_credit_for_ap_restart() {
        crate::preempt::_test_reset(); irq_enter();
        TerminalIrqExit::begin().unwrap().commit();
        assert_eq!(preempt_count(), 0);
    }

    #[test]
    fn non_irq_and_nested_irq_contexts_are_not_normalized() {
        crate::preempt::_test_reset();
        assert!(TerminalIrqExit::begin().is_none());
        irq_enter(); irq_enter();
        assert!(TerminalIrqExit::begin().is_none());
        assert_eq!(preempt_count(), HARDIRQ_OFFSET * 2);
        irq_exit(); irq_exit();
    }
}
