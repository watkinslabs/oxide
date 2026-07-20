use super::{allocation_policy, default_min_free_kbytes, derive_zone_watermarks, AllocationPolicy, WatermarkTunables, DEFAULT_WATERMARK_SCALE_FACTOR, KIB_BYTES, MIN_FREE_KBYTES_CEILING, MIN_FREE_KBYTES_FLOOR};

const PAGE_BYTES: u64 = 4096;

#[test]
fn linux_default_min_free_is_sqrt_with_documented_clamps() {
    assert_eq!(default_min_free_kbytes(0, PAGE_BYTES), MIN_FREE_KBYTES_FLOOR);
    let huge_pages = MIN_FREE_KBYTES_CEILING.saturating_mul(MIN_FREE_KBYTES_CEILING).saturating_mul(KIB_BYTES) / PAGE_BYTES;
    assert_eq!(default_min_free_kbytes(huge_pages, PAGE_BYTES), MIN_FREE_KBYTES_CEILING);
}

#[test]
fn zone_watermarks_are_ordered_and_scale_with_managed_memory() {
    let tunables = WatermarkTunables { min_free_kbytes: Some(4096), watermark_scale_factor: DEFAULT_WATERMARK_SCALE_FACTOR };
    let zone = derive_zone_watermarks(262_144, 524_288, tunables, PAGE_BYTES);
    assert!(zone.min > 0);
    assert!(zone.min < zone.low && zone.low < zone.high);
    assert_eq!(zone.min, (4096 * KIB_BYTES / PAGE_BYTES) / 2);
}

#[test]
fn allocation_wakes_at_low_and_reclaims_only_before_min() {
    super::MANAGED_PAGES.store(1_000_000, core::sync::atomic::Ordering::Release);
    super::MIN_PAGES.store(100, core::sync::atomic::Ordering::Release);
    super::LOW_PAGES.store(200, core::sync::atomic::Ordering::Release);
    super::HIGH_PAGES.store(300, core::sync::atomic::Ordering::Release);
    assert_eq!(allocation_policy(500, 1), AllocationPolicy::Allow);
    assert_eq!(allocation_policy(150, 1), AllocationPolicy::WakeBackground);
    assert_eq!(allocation_policy(100, 1), AllocationPolicy::DirectReclaim);
}
