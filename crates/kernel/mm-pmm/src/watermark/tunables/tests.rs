// Provenance: the two VM tunables have to REACH the watermark producer.
// Before this, `vm.min_free_kbytes` was a procfs-owned cell an operator could
// write and read back with nothing downstream of it, and
// `vm.watermark_scale_factor` did not exist. These tests drive the setters and
// assert the derived marks moved, which is the only thing that makes the knobs
// real.

use super::*;
use crate::watermark::{derive_zone_watermarks, PublishGuard, MIN_FREE_KBYTES_FLOOR};

const PAGE_BYTES: u64 = 4096;

/// Restore the boot state so an ordering between tests cannot matter. The
/// publish right is held for the whole of each test, so no other producer can
/// observe a half-restored tunable set.
fn reset() {
    USER_MIN_FREE_KBYTES.store(0, Ordering::Release);
    SCALE_FACTOR.store(DEFAULT_WATERMARK_SCALE_FACTOR, Ordering::Release);
}

#[test]
fn an_unset_min_free_kbytes_reports_the_kernel_derived_default() {
    let _right = PublishGuard::acquire();
    reset();
    assert_eq!(current().min_free_kbytes, None);
    assert_eq!(effective_min_free_kbytes(0, PAGE_BYTES), MIN_FREE_KBYTES_FLOOR);
    let pages = 262_144u64;
    assert_eq!(effective_min_free_kbytes(pages, PAGE_BYTES),
               crate::watermark::default_min_free_kbytes(pages, PAGE_BYTES));
}

#[test]
fn a_written_min_free_kbytes_is_what_the_derivation_uses() {
    let _right = PublishGuard::acquire();
    reset();
    let before = derive_zone_watermarks(262_144, 262_144, current(), PAGE_BYTES, false);
    set_min_free_kbytes(65_536);
    assert_eq!(current().min_free_kbytes, Some(65_536));
    assert_eq!(effective_min_free_kbytes(262_144, PAGE_BYTES), 65_536);
    let after = derive_zone_watermarks(262_144, 262_144, current(), PAGE_BYTES, false);
    assert!(after.min > before.min, "a larger reserve raises the minimum: {before:?} -> {after:?}");
    // Zero hands the derivation back to the kernel.
    set_min_free_kbytes(0);
    assert_eq!(current().min_free_kbytes, None);
    reset();
}

#[test]
fn the_scale_factor_widens_the_gap_between_the_marks() {
    let _right = PublishGuard::acquire();
    reset();
    set_min_free_kbytes(4096);
    let narrow = derive_zone_watermarks(262_144, 262_144, current(), PAGE_BYTES, false);
    set_watermark_scale_factor(SCALE_FACTOR_MAX);
    assert_eq!(live_watermark_scale_factor(), SCALE_FACTOR_MAX);
    let wide = derive_zone_watermarks(262_144, 262_144, current(), PAGE_BYTES, false);
    assert_eq!(wide.min, narrow.min, "the scale factor moves the gap, not the minimum");
    assert!(wide.low - wide.min > narrow.low - narrow.min, "{narrow:?} -> {wide:?}");
    reset();
}

#[test]
fn the_scale_factor_is_clamped_to_the_range_the_leaf_accepts() {
    assert_eq!(clamp_scale_factor(0), SCALE_FACTOR_MIN);
    assert_eq!(clamp_scale_factor(SCALE_FACTOR_MAX + 1), SCALE_FACTOR_MAX);
    assert_eq!(clamp_scale_factor(u64::MAX), SCALE_FACTOR_MAX);
    assert_eq!(clamp_scale_factor(10), 10);
    let _right = PublishGuard::acquire();
    reset();
    set_watermark_scale_factor(0);
    assert_eq!(live_watermark_scale_factor(), SCALE_FACTOR_MIN);
    reset();
}
