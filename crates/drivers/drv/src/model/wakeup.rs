use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

const NO_WAKE_IRQ: u32 = u32::MAX;
const CAPABLE: u8 = 1 << 0;
const ENABLED: u8 = 1 << 1;

pub(crate) struct Wakeup {
    flags: AtomicU8,
    irq: AtomicU32,
}

impl Wakeup {
    pub(crate) const fn new() -> Self {
        Self { flags: AtomicU8::new(0), irq: AtomicU32::new(NO_WAKE_IRQ) }
    }

    pub(crate) fn init(&self, enabled: bool) {
        self.flags.store(if enabled { CAPABLE | ENABLED } else { 0 }, Ordering::Release);
    }

    pub(crate) fn set_capable(&self, capable: bool) {
        let _ = self.flags.fetch_update(Ordering::AcqRel, Ordering::Acquire, |flags| {
            Some(if capable { flags | CAPABLE } else { flags & !(CAPABLE | ENABLED) })
        });
    }

    pub(crate) fn set_enabled(&self, enabled: bool) -> bool {
        self.flags.fetch_update(Ordering::AcqRel, Ordering::Acquire, |flags| {
            if enabled && flags & CAPABLE == 0 { None }
            else { Some(if enabled { flags | ENABLED } else { flags & !ENABLED }) }
        }).is_ok()
    }

    pub(crate) fn capable(&self) -> bool { self.flags.load(Ordering::Acquire) & CAPABLE != 0 }

    pub(crate) fn may_wakeup(&self) -> bool {
        self.flags.load(Ordering::Acquire) & (CAPABLE | ENABLED) == CAPABLE | ENABLED
    }

    pub(crate) fn set_irq(&self, irq: Option<u32>) {
        self.irq.store(irq.unwrap_or(NO_WAKE_IRQ), Ordering::Release);
    }

    pub(crate) fn irq(&self) -> Option<u32> {
        match self.irq.load(Ordering::Acquire) { NO_WAKE_IRQ => None, irq => Some(irq) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_is_the_gate_and_policy_is_independent() {
        let wakeup = Wakeup::new();
        assert!(!wakeup.set_enabled(true));
        wakeup.set_capable(true);
        assert!(wakeup.set_enabled(true));
        assert!(wakeup.may_wakeup());
        wakeup.set_capable(false);
        assert!(!wakeup.may_wakeup());
        wakeup.set_capable(true);
        assert!(!wakeup.may_wakeup(), "capability changes must not resurrect old policy");
    }

    #[test]
    fn irq_zero_is_not_confused_with_no_irq() {
        let wakeup = Wakeup::new();
        wakeup.set_irq(Some(0));
        assert_eq!(wakeup.irq(), Some(0));
        wakeup.set_irq(None);
        assert_eq!(wakeup.irq(), None);
    }
}
