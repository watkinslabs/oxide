//! Lock-free witnesses for the hibernation IRQ-restore diagnostic window.

#[cfg(feature = "debug-hibernate")]
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct HibernateWitness {
    pub active: bool,
    pub stage: u32,
    pub local_bits: u32,
    pub process_bits: u32,
    pub slot: u32,
}

#[cfg(feature = "debug-hibernate")]
static ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "debug-hibernate")]
static STAGE: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "debug-hibernate")]
static LOCAL_BITS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "debug-hibernate")]
static PROCESS_BITS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "debug-hibernate")]
static SLOT: AtomicU32 = AtomicU32::new(u32::MAX);

/// Bracket the first IRQ admission during hibernation recovery diagnostics.
/// Off-feature builds compile this to nothing. # C: O(1)
#[inline(always)]
pub fn hibernate_irq_restore(active: bool) {
    #[cfg(feature = "debug-hibernate")]
    if active {
        STAGE.store(0, Ordering::Relaxed);
        LOCAL_BITS.store(0, Ordering::Relaxed);
        PROCESS_BITS.store(0, Ordering::Relaxed);
        SLOT.store(u32::MAX, Ordering::Relaxed);
        ACTIVE.store(true, Ordering::Release);
    } else {
        ACTIVE.store(false, Ordering::Release);
    }
    #[cfg(not(feature = "debug-hibernate"))]
    let _ = active;
}

/// Lock-free state consumable by watchdog/NMI diagnostics. # C: O(1)
/// Snapshot the bounded hibernation softirq witness. # C: O(1)
pub fn hibernate_witness() -> HibernateWitness {
    #[cfg(feature = "debug-hibernate")]
    return HibernateWitness {
        active: ACTIVE.load(Ordering::Acquire),
        stage: STAGE.load(Ordering::Acquire),
        local_bits: LOCAL_BITS.load(Ordering::Relaxed),
        process_bits: PROCESS_BITS.load(Ordering::Relaxed),
        slot: SLOT.load(Ordering::Relaxed),
    };
    #[cfg(not(feature = "debug-hibernate"))]
    HibernateWitness::default()
}

#[inline(always)]
/// Publish one bounded diagnostic stage. # C: O(1)
pub(crate) fn witness_stage(stage: u32, local: u32, process: u32, slot: usize) {
    #[cfg(feature = "debug-hibernate")]
    if ACTIVE.load(Ordering::Acquire) {
        LOCAL_BITS.store(local, Ordering::Relaxed);
        PROCESS_BITS.store(process, Ordering::Relaxed);
        SLOT.store(slot as u32, Ordering::Relaxed);
        STAGE.store(stage, Ordering::Release);
    }
    #[cfg(not(feature = "debug-hibernate"))]
    let _ = (stage, local, process, slot);
}

#[cfg(all(test, feature = "debug-hibernate"))]
mod tests {
    use super::*;

    #[test]
    fn witness_survives_without_recursive_logging() {
        hibernate_irq_restore(true);
        witness_stage(7, 0x12, 0x40, 6);
        assert_eq!(hibernate_witness(), HibernateWitness {
            active: true, stage: 7, local_bits: 0x12, process_bits: 0x40, slot: 6,
        });
        hibernate_irq_restore(false);
        assert!(!hibernate_witness().active);
    }
}
