//! Zone watermark policy.  The buddy's managed/free snapshot remains the
//! allocator truth; this module derives Linux-style thresholds from it and
//! decides when allocation must wake background or direct reclaim.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::PmmSnapshot;

/// Linux `watermark_scale_factor` is expressed in ten-thousandths.
pub const WATERMARK_SCALE_DENOMINATOR: u64 = 10_000;
/// Linux default `vm.watermark_scale_factor`.
pub const DEFAULT_WATERMARK_SCALE_FACTOR: u64 = 10;
/// Linux's `min_free_kbytes` lower clamp used by `calculate_min_free_kbytes`.
pub const MIN_FREE_KBYTES_FLOOR: u64 = 128;
/// Linux's `min_free_kbytes` upper clamp used by `calculate_min_free_kbytes`.
pub const MIN_FREE_KBYTES_CEILING: u64 = 262_144;
/// Kernel page accounting unit for `min_free_kbytes` conversion.
pub const KIB_BYTES: u64 = 1024;

/// User-visible tuning inputs corresponding to Linux VM watermark controls.
/// `min_free_kbytes == None` selects the kernel-derived Linux default.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WatermarkTunables {
    pub min_free_kbytes: Option<u64>,
    pub watermark_scale_factor: u64,
}

impl Default for WatermarkTunables {
    fn default() -> Self {
        Self { min_free_kbytes: None, watermark_scale_factor: DEFAULT_WATERMARK_SCALE_FACTOR }
    }
}

/// One allocator zone's reclaim thresholds, all measured in base pages.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ZoneWatermarks { pub min: u64, pub low: u64, pub high: u64 }

/// PMM-owned observation plus its derived zone watermarks.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct WatermarkSnapshot {
    pub managed_pages: u64,
    pub free_pages: u64,
    pub zone: ZoneWatermarks,
}

/// Allocation action chosen before acquiring the buddy lock.  The actual
/// allocation remains the sole owner of a page; policy only schedules reclaim.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AllocationPolicy { Allow, WakeBackground, DirectReclaim }

static MANAGED_PAGES: AtomicU64 = AtomicU64::new(0);
static MIN_PAGES: AtomicU64 = AtomicU64::new(0);
static LOW_PAGES: AtomicU64 = AtomicU64::new(0);
static HIGH_PAGES: AtomicU64 = AtomicU64::new(0);

/// Apply allocation-side watermark policy before the buddy takes ownership of
/// a frame. The direct path is kernel-only because hosted PMM fixtures have no
/// address-space/swap owner; both paths use the same LRU transaction.
/// # C: O(1) plus at most one direct reclaim transaction
pub(crate) fn before_allocation(free_pages: u64, requested_pages: u64) {
    match allocation_policy(free_pages, requested_pages) {
        AllocationPolicy::Allow => {}
        AllocationPolicy::WakeBackground => {
            #[cfg(target_os = "oxide-kernel")]
            crate::kswapd::wake_kswapd();
        }
        AllocationPolicy::DirectReclaim => {
            #[cfg(target_os = "oxide-kernel")]
            {
                crate::kswapd::wake_kswapd();
                crate::kswapd::direct_reclaim_once();
            }
        }
    }
}

/// Wake background reclaim if a successful allocation left the zone below its
/// low watermark. # C: O(1)
pub(crate) fn after_allocation(free_pages: u64) {
    if matches!(allocation_policy(free_pages, 0), AllocationPolicy::WakeBackground | AllocationPolicy::DirectReclaim) {
        #[cfg(target_os = "oxide-kernel")]
        crate::kswapd::wake_kswapd();
    }
}

/// Calculate the Linux default for `min_free_kbytes`: sqrt(lowmem_kbytes *
/// 16), clamped to Linux's documented floor and ceiling. # C: O(1)
pub fn default_min_free_kbytes(managed_pages: u64, page_bytes: u64) -> u64 {
    let lowmem_kbytes = managed_pages.saturating_mul(page_bytes) / KIB_BYTES;
    let target = integer_sqrt(lowmem_kbytes.saturating_mul(16));
    target.clamp(MIN_FREE_KBYTES_FLOOR, MIN_FREE_KBYTES_CEILING)
}

/// Derive min/low/high exactly as Linux's per-zone watermark update does for
/// a normal managed zone: min is proportional to managed memory and the
/// low/high distance is at least min/4 or scale-factor coverage. # C: O(1)
pub fn derive_zone_watermarks(
    managed_pages: u64,
    total_managed_pages: u64,
    tunables: WatermarkTunables,
    page_bytes: u64,
) -> ZoneWatermarks {
    if managed_pages == 0 || total_managed_pages == 0 || page_bytes == 0 { return ZoneWatermarks::default(); }
    let min_kbytes = tunables.min_free_kbytes.unwrap_or_else(|| default_min_free_kbytes(total_managed_pages, page_bytes));
    let total_min_pages = min_kbytes.saturating_mul(KIB_BYTES) / page_bytes;
    let min = total_min_pages.saturating_mul(managed_pages) / total_managed_pages;
    let scale = managed_pages.saturating_mul(tunables.watermark_scale_factor) / WATERMARK_SCALE_DENOMINATOR;
    let gap = core::cmp::max(min / 4, scale);
    ZoneWatermarks { min, low: min.saturating_add(gap), high: min.saturating_add(gap.saturating_mul(2)) }
}

/// Publish the boot allocator's one current normal zone.  The global records
/// only derived thresholds; live free state always comes from `Pmm::snapshot`.
/// # C: O(1)
pub fn install(snapshot: PmmSnapshot) {
    let zone = derive_zone_watermarks(snapshot.managed_pages, snapshot.managed_pages, WatermarkTunables::default(), hal::PAGE_SIZE_BYTES);
    MANAGED_PAGES.store(snapshot.managed_pages, Ordering::Release);
    MIN_PAGES.store(zone.min, Ordering::Release);
    LOW_PAGES.store(zone.low, Ordering::Release);
    HIGH_PAGES.store(zone.high, Ordering::Release);
}

/// Return the currently published policy and live buddy free count. # C: O(1)
pub fn watermark_snapshot(free_pages: u64) -> Option<WatermarkSnapshot> {
    let managed_pages = MANAGED_PAGES.load(Ordering::Acquire);
    if managed_pages == 0 { return None; }
    Some(WatermarkSnapshot {
        managed_pages, free_pages,
        zone: ZoneWatermarks {
            min: MIN_PAGES.load(Ordering::Acquire), low: LOW_PAGES.load(Ordering::Acquire), high: HIGH_PAGES.load(Ordering::Acquire),
        },
    })
}

/// Decide allocation reclaim policy for `requested_pages`. Linux wakes
/// kswapd below low and performs direct reclaim only when an allocation would
/// cross min; higher-order callers pass their exact requested span. # C: O(1)
pub fn allocation_policy(free_pages: u64, requested_pages: u64) -> AllocationPolicy {
    let Some(snapshot) = watermark_snapshot(free_pages) else { return AllocationPolicy::Allow; };
    let remaining = free_pages.saturating_sub(requested_pages);
    if remaining < snapshot.zone.min { AllocationPolicy::DirectReclaim }
    else if remaining < snapshot.zone.low { AllocationPolicy::WakeBackground }
    else { AllocationPolicy::Allow }
}

fn integer_sqrt(value: u64) -> u64 {
    if value < 2 { return value; }
    let mut left = 1u64;
    let mut right = core::cmp::min(value, u32::MAX as u64);
    let mut answer = 1u64;
    while left <= right {
        let middle = left + (right - left) / 2;
        if middle <= value / middle { answer = middle; left = middle + 1; }
        else { right = middle - 1; }
    }
    answer
}

#[cfg(test)]
mod tests;
