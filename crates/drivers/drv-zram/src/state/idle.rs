use block::{BlockError, KResult};
use hal::TimerOps;

use super::{Slot, Zram};

/// Number of monotonic nanoseconds in one Linux `idle` seconds unit.
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Linux post-processing only marks resident, independently stored objects
/// idle; same-filled, backed, loading, and writeback slots are excluded.
fn idle_eligible(slot: &Slot) -> bool {
    matches!(slot, Slot::Packed { .. } | Slot::Raw { .. })
}

/// Architecture monotonic time used by zram entry access tracking.
/// # C: O(1)
pub(crate) fn monotonic_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

impl Zram {
    /// Mark Linux zram entries idle using `all` or an access-age in seconds.
    /// # C: O(zram pages)
    pub fn mark_idle_text(&self, text: &str) -> KResult<()> {
        self.require_initialized()?;
        let text = text.trim();
        let cutoff = if text == "all" { None } else {
            let age_ns = text.parse::<u64>().map_err(|_| BlockError::Einval)?
                .checked_mul(NANOSECONDS_PER_SECOND).ok_or(BlockError::Einval)?;
            Some(monotonic_ns().saturating_sub(age_ns))
        };
        let mut state = self.state.lock();
        for index in 0..state.slots.len() {
            let slot = state.slots.get(index).expect("zram slot index validated by table length");
            let idle = idle_eligible(slot)
                && cutoff.is_none_or(|cutoff| state.slots.last_access_ns(index).expect("zram slot index validated by table length") <= cutoff);
            state.slots.set_idle(index, idle)?;
        }
        Ok(())
    }
}
