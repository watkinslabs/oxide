//! Which raw NT ordinals the boot log has already named.
//!
//! The ordinal trace exists to record one mapping — raw ordinal to the service
//! that answered it — for the module a boot actually loaded. A mapping has one
//! line per distinct pair, so a run that issues the same ordinal 296 times owes
//! the log one line, not 296. Emitting it per call turns a table into a storm
//! and puts one synchronous console write in every NT syscall.
//!
//! The claim decision lives here, ungated, so it compiles and is tested; the
//! dispatch slot that writes the line stays kernel-only (docs/53).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Distinct ordinal/service pairs the table can name. A shipped module's raw
/// ordinal set is far smaller; the overflow budget below covers a caller that
/// walks the number space instead.
pub const PAIR_SLOTS: usize = 512;

/// Lines left for pairs the table can no longer hold. A caller sweeping
/// ordinals must not become the boot log.
pub const OVERFLOW_REPORTS: u32 = 64;

/// Empty slot marker. A claimed slot stores `key + 1`, so a real pair whose
/// ordinal and service are both zero is still distinguishable from empty.
const EMPTY: u64 = 0;

/// One boot's record of which ordinal/service pairs the log already names.
pub struct OrdinalReports { slots: [AtomicU64; PAIR_SLOTS], overflow: AtomicU32 }

impl OrdinalReports {
    /// # C: O(1)
    #[allow(clippy::declare_interior_mutable_const)]
    pub const fn new() -> Self {
        const EMPTY_SLOT: AtomicU64 = AtomicU64::new(EMPTY);
        Self { slots: [EMPTY_SLOT; PAIR_SLOTS], overflow: AtomicU32::new(0) }
    }

    /// Whether this ordinal/service pair still owes the log a line. True once
    /// per distinct pair, so a misroute of an ordinal the log already named
    /// still prints: the pair, not the ordinal alone, is the mapping entry.
    /// # C: O(PAIR_SLOTS) worst case, O(1) once a pair is seated
    /// # Lk: none
    pub fn claim(&self, ordinal: u32, service: u32) -> bool {
        let key = (((ordinal as u64) << 32) | service as u64).wrapping_add(1);
        let mut index = (key ^ (key >> 17)) as usize % PAIR_SLOTS;
        for _ in 0..PAIR_SLOTS {
            let slot = &self.slots[index];
            match slot.load(Ordering::Relaxed) {
                EMPTY => match slot.compare_exchange(EMPTY, key, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => return true,
                    // A racing claim took the slot; re-read it rather than
                    // stepping on, so both threads agree on one owner.
                    Err(taken) if taken == key => return false,
                    Err(_) => {}
                },
                seen if seen == key => return false,
                _ => {}
            }
            index = (index + 1) % PAIR_SLOTS;
        }
        self.overflow.fetch_add(1, Ordering::Relaxed) < OVERFLOW_REPORTS
    }
}

impl Default for OrdinalReports { fn default() -> Self { Self::new() } }

#[cfg(test)]
#[path = "nt_ordinal_report/tests.rs"]
mod tests;
