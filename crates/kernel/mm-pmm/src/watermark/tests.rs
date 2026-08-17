use super::{allocation_policy, publish, PublishGuard, ZoneWatermarks, default_min_free_kbytes, derive_zone_watermarks, direct_reclaim_allowed, AllocationPolicy, WatermarkTunables, DEFAULT_WATERMARK_SCALE_FACTOR, KIB_BYTES, MIN_FREE_KBYTES_CEILING, MIN_FREE_KBYTES_FLOOR};

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
    let zone = derive_zone_watermarks(262_144, 524_288, tunables, PAGE_BYTES, false);
    assert!(zone.min > 0);
    assert!(zone.min < zone.low && zone.low < zone.high && zone.high < zone.promo);
    assert_eq!(zone.min, (4096 * KIB_BYTES / PAGE_BYTES) / 2);
}

#[test]
fn allocation_wakes_at_low_and_reclaims_only_before_min() {
    // The guard is held across the writes AND the reads below: it is the
    // publish right, so no other producer can land inside this window.
    let right = PublishGuard::acquire();
    publish(&right, 1_000_000, ZoneWatermarks { min: 100, low: 200, high: 300, promo: 400 });
    assert_eq!(allocation_policy(500, 1), AllocationPolicy::Allow);
    assert_eq!(allocation_policy(150, 1), AllocationPolicy::WakeBackground);
    assert_eq!(allocation_policy(100, 1), AllocationPolicy::DirectReclaim);
}

#[test]
fn direct_reclaim_requires_blockable_non_flusher_context() {
    assert!(direct_reclaim_allowed(false, false));
    assert!(!direct_reclaim_allowed(true, false));
    assert!(!direct_reclaim_allowed(false, true));
    assert!(!direct_reclaim_allowed(true, true));
}

#[test]
fn a_capped_zone_takes_a_small_fixed_minimum_and_keeps_the_uncapped_gap() {
    let tunables = WatermarkTunables { min_free_kbytes: Some(4096), watermark_scale_factor: DEFAULT_WATERMARK_SCALE_FACTOR };
    let plain = derive_zone_watermarks(262_144, 524_288, tunables, PAGE_BYTES, false);
    let capped = derive_zone_watermarks(262_144, 524_288, tunables, PAGE_BYTES, true);
    assert_eq!(capped.min, super::CAPPED_MIN_CEILING);
    assert!(capped.min < plain.min);
    // Each mark sits one gap above the last, and the gap is the uncapped one.
    assert_eq!(capped.low - capped.min, plain.low - plain.min);
    assert_eq!(capped.high - capped.low, plain.high - plain.low);
    assert_eq!(capped.promo - capped.high, plain.promo - plain.high);
}

#[test]
fn a_tiny_capped_zone_takes_the_documented_floor() {
    let tunables = WatermarkTunables::default();
    let capped = derive_zone_watermarks(64, 524_288, tunables, PAGE_BYTES, true);
    assert_eq!(capped.min, super::CAPPED_MIN_FLOOR);
}
