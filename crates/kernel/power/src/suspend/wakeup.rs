// Wakeup-event accounting per `32a§6`.
//
// One word, two fields: registered events in the high half, events in progress
// in the low half. Both move in a single atomic op so a reader never sees a
// deactivation half-applied — an event that has left "in progress" but not yet
// arrived in "registered" would read as no event at all, which is exactly the
// lost wakeup this accounting exists to prevent.
//
// The counters are a plain struct rather than module statics so a test can own
// an instance; the system-wide one is [`SYSTEM`].

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Width of the in-progress field. The registered count occupies the rest.
const IN_PROGRESS_BITS: u32 = 16;
/// Mask of the in-progress field; also the increment that moves one event from
/// in-progress to registered in a single add.
const MAX_IN_PROGRESS: u32 = (1 << IN_PROGRESS_BITS) - 1;

/// One system's wakeup-event accounting.
pub struct WakeupCounters {
    /// Registered events (high half) and events in progress (low half).
    combined: AtomicU32,
    /// Whether the registered-count comparison is armed.
    check_enabled: AtomicBool,
    /// The count armed against.
    saved: AtomicU32,
    /// Unconditional aborts posted by a hard wakeup source.
    abort: AtomicU32,
    /// Up to two IRQ numbers credited with the wakeup.
    wakeup_irq: [AtomicU32; 2],
}

/// A counter snapshot: registered events, events in progress.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Counts { pub registered: u32, pub in_progress: u32 }

impl WakeupCounters {
    /// A zeroed set of counters. # C: O(1)
    pub const fn new() -> Self {
        WakeupCounters {
            combined: AtomicU32::new(0),
            check_enabled: AtomicBool::new(false),
            saved: AtomicU32::new(0),
            abort: AtomicU32::new(0),
            wakeup_irq: [AtomicU32::new(0), AtomicU32::new(0)],
        }
    }

    /// Split the combined word. # C: O(1)
    pub fn counts(&self) -> Counts { split(self.combined.load(Ordering::SeqCst)) }

    /// Whether the registered-count comparison is armed. # C: O(1)
    pub fn check_enabled(&self) -> bool { self.check_enabled.load(Ordering::SeqCst) }

    /// A wakeup source became active: one more event in progress.
    /// Safe from interrupt context.
    /// # C: O(1)
    pub fn source_activate(&self) { self.combined.fetch_add(1, Ordering::SeqCst); }

    /// A wakeup source finished: the event moves from in-progress to
    /// registered. One add does both, so no reader observes it in neither.
    /// # C: O(1)
    pub fn source_deactivate(&self) { self.combined.fetch_add(MAX_IN_PROGRESS, Ordering::SeqCst); }

    /// Post an unconditional abort, the "hard" wakeup a source reports when it
    /// knows the machine must not sleep.
    /// # C: O(1)
    pub fn system_wakeup(&self) { self.abort.fetch_add(1, Ordering::SeqCst); }

    /// Withdraw one unconditional abort, never below zero. # C: O(1)
    pub fn system_cancel_wakeup(&self) {
        let _ = self.abort.fetch_update(Ordering::SeqCst, Ordering::SeqCst,
            |v| if v > 0 { Some(v - 1) } else { None });
    }

    /// Credit `irq` with a wakeup and post the abort. Records at most two IRQ
    /// numbers; a third arriving posts no further abort, matching the
    /// reference's behaviour of only crediting what it can name.
    /// # C: O(1)
    pub fn system_irq_wakeup(&self, irq: u32) {
        let mut credited = irq;
        if self.wakeup_irq[0].load(Ordering::SeqCst) == 0 {
            self.wakeup_irq[0].store(irq, Ordering::SeqCst);
        } else if self.wakeup_irq[1].load(Ordering::SeqCst) == 0 {
            self.wakeup_irq[1].store(irq, Ordering::SeqCst);
        } else { credited = 0; }
        if credited != 0 { self.system_wakeup(); }
    }

    /// The IRQ credited with the wakeup, zero when none is. # C: O(1)
    pub fn wakeup_irq(&self) -> u32 { self.wakeup_irq[0].load(Ordering::SeqCst) }

    /// Clear the recorded wakeup IRQs, and with `irq == 0` the abort count too.
    /// A nonzero `irq` shifts that entry out and keeps the abort standing.
    /// # C: O(1)
    pub fn wakeup_clear(&self, irq: u32) {
        if irq != 0 && self.wakeup_irq[0].load(Ordering::SeqCst) == irq {
            let second = self.wakeup_irq[1].load(Ordering::SeqCst);
            self.wakeup_irq[0].store(second, Ordering::SeqCst);
        } else {
            self.wakeup_irq[0].store(0, Ordering::SeqCst);
        }
        self.wakeup_irq[1].store(0, Ordering::SeqCst);
        if irq == 0 { self.abort.store(0, Ordering::SeqCst); }
    }

    /// Whether a transition in progress must be abandoned.
    ///
    /// True when the check is armed and either the registered count has moved
    /// off the armed value or an event is in progress; or, regardless of
    /// arming, an unconditional abort stands. Reporting true disarms the
    /// check, so the same registered-count movement is not reported twice.
    /// # C: O(1)
    pub fn wakeup_pending(&self) -> bool {
        let mut moved = false;
        if self.check_enabled.load(Ordering::SeqCst) {
            let c = self.counts();
            moved = c.registered != self.saved.load(Ordering::SeqCst) || c.in_progress > 0;
            if moved { self.check_enabled.store(false, Ordering::SeqCst); }
        }
        moved || self.abort.load(Ordering::SeqCst) > 0
    }

    /// Read the registered count. Returns the count and whether no event is in
    /// progress; a caller that cares blocks until the second is true.
    /// # C: O(1)
    pub fn get_wakeup_count(&self) -> (u32, bool) {
        let c = self.counts();
        (c.registered, c.in_progress == 0)
    }

    /// Arm the comparison against `count`. Succeeds only when `count` is still
    /// the registered count and nothing is in progress — that pairing is what
    /// closes the window between userspace reading the count and deciding to
    /// suspend. A failure leaves the check disarmed.
    /// # C: O(1)
    pub fn save_wakeup_count(&self, count: u32) -> bool {
        self.check_enabled.store(false, Ordering::SeqCst);
        let c = self.counts();
        if c.registered == count && c.in_progress == 0 {
            self.saved.store(count, Ordering::SeqCst);
            self.check_enabled.store(true, Ordering::SeqCst);
        }
        self.check_enabled.load(Ordering::SeqCst)
    }

    /// Disarm without arming anything else. Run when a transition finishes.
    /// # C: O(1)
    pub fn disarm(&self) { self.check_enabled.store(false, Ordering::SeqCst); }
}

fn split(comb: u32) -> Counts {
    Counts { registered: comb >> IN_PROGRESS_BITS, in_progress: comb & MAX_IN_PROGRESS }
}

/// The machine's wakeup accounting.
pub static SYSTEM: WakeupCounters = WakeupCounters::new();

/// `32a§6`: whether the transition in progress must be abandoned. # C: O(1)
pub fn pm_wakeup_pending() -> bool { SYSTEM.wakeup_pending() }

/// Post an unconditional abort and wake suspend-to-idle. Safe from interrupt
/// context; this is what an IRQ handler calls when its device woke the machine.
/// # C: O(1)
pub fn pm_system_wakeup() {
    SYSTEM.system_wakeup();
    super::s2idle::s2idle_wake();
}

/// Credit `irq` with the wakeup, then [`pm_system_wakeup`]. # C: O(1)
pub fn pm_system_irq_wakeup(irq: u32) {
    SYSTEM.system_irq_wakeup(irq);
    super::s2idle::s2idle_wake();
}

/// Withdraw one unconditional abort. # C: O(1)
pub fn pm_system_cancel_wakeup() { SYSTEM.system_cancel_wakeup(); }

/// Clear recorded wakeup IRQs, and the abort count when `irq` is zero.
/// # C: O(1)
pub fn pm_wakeup_clear(irq: u32) { SYSTEM.wakeup_clear(irq); }

/// The IRQ credited with the last wakeup, zero when none is. # C: O(1)
pub fn pm_wakeup_irq() -> u32 { SYSTEM.wakeup_irq() }

#[cfg(test)]
#[path = "wakeup/tests.rs"]
mod tests;
