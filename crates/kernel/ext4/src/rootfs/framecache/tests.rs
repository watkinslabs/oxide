// Pure index/range arithmetic for invalidate_range/writeback_range. Frame data
// paths are covered by the hosted ext4-image fixture test `frame_coherency_image`.
use alloc::collections::BTreeMap;

use super::{shadow_budget, trim_shadows, SHADOW_FLOOR};

const PG: u64 = 4096;

fn inv_bounds(start: u64, end: u64) -> (u64, u64) {
    let lo = (start + PG - 1) / PG;
    let hi = if end == u64::MAX { u64::MAX } else { end / PG };
    (lo, hi)
}

#[test]
fn invalidate_drops_only_fully_covered_pages() {
    assert_eq!(inv_bounds(0, 2 * PG), (0, 2));
    assert_eq!(inv_bounds(1, 2 * PG), (1, 2));
    assert_eq!(inv_bounds(0, 2 * PG - 1), (0, 1));
    let len = 3 * PG + 100;
    let floored = len & !(PG - 1);
    let (lo, hi) = inv_bounds(floored, u64::MAX);
    assert_eq!(lo, 3);
    assert_eq!(hi, u64::MAX);
}

fn wb_bounds(start: u64, end: u64) -> (u64, u64) {
    let lo = start / PG;
    let hi = if end == u64::MAX { u64::MAX } else { (end + PG - 1) / PG };
    (lo, hi)
}

#[test]
fn writeback_range_covers_intersecting_pages() {
    assert_eq!(wb_bounds(0, 1), (0, 1));
    assert_eq!(wb_bounds(PG, PG + 1), (1, 2));
    assert_eq!(wb_bounds(100, 2 * PG + 50), (0, 3));
    assert_eq!(wb_bounds(PG, u64::MAX), (1, u64::MAX));
}

#[test]
fn eviction_shadow_history_is_bounded_when_resident_cache_is_empty() {
    let mut shadows = (0..SHADOW_FLOOR as u64 + 5).map(|idx| (idx, idx)).collect::<BTreeMap<_, _>>();

    trim_shadows(&mut shadows, 0);

    assert_eq!(shadows.len(), SHADOW_FLOOR);
    assert!(!shadows.contains_key(&0));
    assert!(shadows.contains_key(&(SHADOW_FLOOR as u64 + 4)));
    assert_eq!(shadow_budget(3), SHADOW_FLOOR + 6);
}
