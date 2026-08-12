//! Bounded transfer-completion handoff from xHCI IRQ to process context.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ring::TRBS_PER_SEGMENT;

struct Slot { trb_pa: AtomicU64, meta: AtomicU64 }

impl Slot {
    const fn new() -> Self { Self { trb_pa: AtomicU64::new(0), meta: AtomicU64::new(0) } }
}

/// One controller's bounded set of transfer completions waiting for consumers. # C: O(1)
pub struct TransferCompletions { slots: [Slot; TRBS_PER_SEGMENT] }

impl TransferCompletions {
    /// Create an empty handoff table sized to one hardware event-ring segment. # C: O(1)
    pub const fn new() -> Self { Self { slots: [const { Slot::new() }; TRBS_PER_SEGMENT] } }

    /// Publish one completed transfer without overwriting another completion. # C: O(event ring)
    pub fn publish(&self, trb_pa: u64, meta: u64) -> bool {
        if trb_pa == 0 { return false; }
        for slot in &self.slots {
            let present = slot.trb_pa.load(Ordering::Acquire);
            if present == trb_pa { return true; }
            if present == 0 {
                // The xHCI hard handler is the sole producer for one binding.
                slot.meta.store(meta, Ordering::Relaxed);
                slot.trb_pa.store(trb_pa, Ordering::Release);
                return true;
            }
        }
        false
    }

    /// Claim exactly the completed transfer identified by its event TRB address. # C: O(event ring)
    pub fn take(&self, trb_pa: u64) -> Option<u64> {
        if trb_pa == 0 { return None; }
        for slot in &self.slots {
            if slot.trb_pa.load(Ordering::Acquire) != trb_pa { continue; }
            let meta = slot.meta.load(Ordering::Relaxed);
            if slot.trb_pa.compare_exchange(trb_pa, 0, Ordering::AcqRel, Ordering::Acquire).is_ok() { return Some(meta); }
        }
        None
    }

    /// Discard pending completions only after controller IRQ delivery is quiesced. # C: O(event ring)
    pub fn clear(&self) {
        for slot in &self.slots { slot.trb_pa.store(0, Ordering::Release); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_completions_for_independent_transfer_owners() {
        let completions = TransferCompletions::new();
        assert!(completions.publish(0x1000, 0x11));
        assert!(completions.publish(0x2000, 0x22));
        assert_eq!(completions.take(0x2000), Some(0x22));
        assert_eq!(completions.take(0x1000), Some(0x11));
    }

    #[test]
    fn does_not_replace_the_first_completion_for_one_trb() {
        let completions = TransferCompletions::new();
        assert!(completions.publish(0x1000, 0x11));
        assert!(completions.publish(0x1000, 0x22));
        assert_eq!(completions.take(0x1000), Some(0x11));
    }

    #[test]
    fn full_table_refuses_new_event_without_losing_prior_events() {
        let completions = TransferCompletions::new();
        for index in 1..=TRBS_PER_SEGMENT { assert!(completions.publish((index * 0x1000) as u64, index as u64)); }
        assert!(!completions.publish(0xdead_0000, 0));
        assert_eq!(completions.take(0x1000), Some(1));
        assert!(completions.publish(0xdead_0000, 0));
    }

    #[test]
    fn clear_discards_only_unclaimed_completions() {
        let completions = TransferCompletions::new();
        assert!(completions.publish(0x1000, 1));
        completions.clear();
        assert_eq!(completions.take(0x1000), None);
    }
}
