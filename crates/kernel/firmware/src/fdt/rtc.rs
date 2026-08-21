//! Persistent-clock owner for the ARM PrimeCell PL031.
//!
//! The retained device tree selects one enabled MMIO resource. Production
//! maps that resource exactly once and retains the owned mapping here; all
//! clock users read the same `RTC_DR` register through this owner.

use core::sync::atomic::{AtomicU64, Ordering};

const RTC_DR: u64 = 0x00;
const NS_PER_SEC: u64 = 1_000_000_000;

/// Published register VA. Zero means no admitted/mapped PL031.
static RTC_BASE_VA: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "aarch64")]
use sync::{Spinlock, TaskList};
#[cfg(target_arch = "aarch64")]
static RTC_MAPPING: Spinlock<Option<mmio_map::Mapping>, TaskList> = Spinlock::new(None);

#[inline]
fn seconds_to_ns(seconds: u32) -> u64 { u64::from(seconds).saturating_mul(NS_PER_SEC) }

#[inline]
fn read_dr(read: impl FnOnce() -> u32) -> u64 { seconds_to_ns(read()) }

/// Discover and map the retained tree's first enabled `arm,pl031` resource.
/// Idempotent: the mapping is created once and remains owned for kernel life.
/// # C: O(struct_block_size + mapped pages)
/// # Ctx: boot CPU, MMU and PMM initialized
#[cfg(target_arch = "aarch64")]
pub fn init() -> bool {
    if RTC_BASE_VA.load(Ordering::Acquire) != 0 { return true; }
    let Some(resource) = super::blob().and_then(::fdt::pl031_rtc) else { return false; };
    let page = hal::PAGE_SIZE_BYTES;
    let page_base = resource.base_pa & !(page - 1);
    let offset = resource.base_pa.checked_sub(page_base).unwrap_or(0);
    // Only RTC_DR is consumed. Do not let a hostile resource length reserve an
    // unbounded kernel-VA span merely because the first register is valid.
    let mapped_bytes = offset.checked_add(core::mem::size_of::<u32>() as u64);
    let pages = mapped_bytes.and_then(|bytes| bytes.checked_add(page - 1))
        .and_then(|bytes| bytes.checked_div(page)).unwrap_or(0);
    if pages == 0 { return false; }
    let mut owner = RTC_MAPPING.lock();
    if RTC_BASE_VA.load(Ordering::Acquire) != 0 { return true; }
    // SAFETY: the enabled DT node admitted this non-RAM device range; this
    // module is its sole mapper and retains the returned owner indefinitely.
    let mapping = unsafe { mmio_map::map_owned(page_base, pages) };
    let Some(base_va) = mapping.base_va().checked_add(offset).filter(|va| *va != 0) else {
        return false;
    };
    *owner = Some(mapping);
    RTC_BASE_VA.store(base_va, Ordering::Release);
    true
}

/// Hosted/non-ARM builds have no PL031 transport. # C: O(1)
#[cfg(not(target_arch = "aarch64"))]
pub fn init() -> bool { false }

/// Read persistent Unix time in nanoseconds from PL031 `RTC_DR`.
/// # C: O(1)
pub fn unix_time_ns() -> Option<u64> {
    let base = RTC_BASE_VA.load(Ordering::Acquire);
    if base == 0 { return None; }
    let address = base.checked_add(RTC_DR)? as *const u32;
    // SAFETY: `init` publishes only after retaining the live device mapping;
    // RTC_DR is a naturally aligned read-only 32-bit PL031 register.
    Some(read_dr(|| unsafe { core::ptr::read_volatile(address) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtc_dr_is_unix_seconds_scaled_once() {
        assert_eq!(read_dr(|| 1_700_000_001), 1_700_000_001_000_000_000);
    }

    #[test]
    fn absent_mapping_has_no_persistent_reading() {
        assert_eq!(unix_time_ns(), None);
    }
}
