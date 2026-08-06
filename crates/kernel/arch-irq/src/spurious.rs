//! Per-line unhandled-interrupt detector.

const UNHANDLED_GAP_NS: u64 = 100_000_000;
const DELIVERY_WINDOW: u32 = 100_000;
const UNHANDLED_LIMIT: u32 = 99_900;
const THREAD_DEFERRED: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqRet { Handled, NotMine, WakeThread }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrqReport {
    pub ret: IrqRet,
    pub threads_handled: u32,
}

impl IrqReport {
    /// Report one non-threaded hard-handler result. # C: O(1)
    pub const fn hard(ret: IrqRet) -> Self { Self { ret, threads_handled: 0 } }
}

#[derive(Clone, Copy)]
pub(crate) struct SpuriousState {
    irq_count: u32,
    irqs_unhandled: u32,
    last_unhandled_ns: u64,
    threads_handled_last: u32,
    disabled: bool,
}

impl SpuriousState {
    pub(crate) const fn new() -> Self {
        Self {
            irq_count: 0,
            irqs_unhandled: 0,
            last_unhandled_ns: 0,
            threads_handled_last: 0,
            disabled: false,
        }
    }

    /// Reset detector state when a descriptor gains or loses its owner. # C: O(1)
    pub(crate) fn reset(&mut self) { *self = Self::new(); }

    /// Report whether the detector has shut down this descriptor. # C: O(1)
    pub(crate) fn disabled(&self) -> bool { self.disabled }

    /// Charge one aggregate handler result. Returns true exactly once when the
    /// line crosses the shutdown threshold. # C: O(1)
    pub(crate) fn note(&mut self, now_ns: u64, report: IrqReport) -> bool {
        if self.disabled { return false; }
        let mut ret = report.ret;
        if ret == IrqRet::WakeThread {
            if self.threads_handled_last & THREAD_DEFERRED == 0 {
                self.threads_handled_last |= THREAD_DEFERRED;
                return false;
            }
            let handled = (report.threads_handled & !THREAD_DEFERRED) | THREAD_DEFERRED;
            if handled != self.threads_handled_last {
                ret = IrqRet::Handled;
                self.threads_handled_last = handled;
            } else {
                ret = IrqRet::NotMine;
            }
        } else if ret == IrqRet::Handled {
            self.threads_handled_last &= !THREAD_DEFERRED;
        }

        if ret == IrqRet::NotMine {
            if now_ns.saturating_sub(self.last_unhandled_ns) > UNHANDLED_GAP_NS {
                self.irqs_unhandled = 1;
            } else {
                self.irqs_unhandled = self.irqs_unhandled.saturating_add(1);
            }
            self.last_unhandled_ns = now_ns;
        }
        if self.irqs_unhandled == 0 { return false; }
        self.irq_count = self.irq_count.saturating_add(1);
        if self.irq_count < DELIVERY_WINDOW { return false; }
        self.irq_count = 0;
        let disable = self.irqs_unhandled > UNHANDLED_LIMIT;
        self.irqs_unhandled = 0;
        if disable { self.disabled = true; }
        disable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hard(ret: IrqRet) -> IrqReport { IrqReport::hard(ret) }

    #[test]
    fn exact_window_boundary_disables_only_above_99900() {
        let mut enabled = SpuriousState::new();
        for _ in 0..99_900 { assert!(!enabled.note(1, hard(IrqRet::NotMine))); }
        for _ in 0..100 { assert!(!enabled.note(1, hard(IrqRet::Handled))); }
        assert!(!enabled.disabled());

        let mut disabled = SpuriousState::new();
        for _ in 0..99_900 { assert!(!disabled.note(1, hard(IrqRet::NotMine))); }
        assert!(!disabled.note(1, hard(IrqRet::NotMine)));
        for _ in 0..98 { assert!(!disabled.note(1, hard(IrqRet::Handled))); }
        assert!(disabled.note(1, hard(IrqRet::Handled)));
        assert!(disabled.disabled());
    }

    #[test]
    fn unhandled_gap_resets_the_burst() {
        let mut state = SpuriousState::new();
        assert!(!state.note(1, hard(IrqRet::NotMine)));
        assert!(!state.note(UNHANDLED_GAP_NS + 2, hard(IrqRet::NotMine)));
        assert_eq!(state.irqs_unhandled, 1);
    }

    #[test]
    fn wake_thread_is_charged_on_the_next_delivery() {
        let mut state = SpuriousState::new();
        let wake0 = IrqReport { ret: IrqRet::WakeThread, threads_handled: 0 };
        let wake1 = IrqReport { ret: IrqRet::WakeThread, threads_handled: 1 };
        assert!(!state.note(1, wake0));
        assert_eq!(state.irq_count, 0);
        assert!(!state.note(2, wake1));
        assert_eq!(state.irqs_unhandled, 0);
        assert!(!state.note(3, wake1));
        assert_eq!(state.irqs_unhandled, 1);
    }
}
