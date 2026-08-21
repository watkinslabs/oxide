//! Hibernation image preallocation budget.

const IO_BYTES: u64 = 4 * 1024 * 1024;

/// Linux-shaped best-effort image target and mandatory allocation ceiling.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Budget {
    pub desired_pages: u64,
    pub reclaim_pages: u64,
    pub max_image_pages: u64,
    pub free_floor_pages: u64,
}

/// Compute one image budget from allocator and reclaim-owner snapshots.
/// `metadata_pages` covers every retained transaction owner. # C: O(1)
pub fn calculate(saveable_pages: u64, free_pages: u64, metadata_pages: u64,
    reclaimable_pages: u64, image_bytes: u64, reserved_bytes: u64,
    page_bytes: u64) -> Budget
{
    let io_pages = div_ceil(IO_BYTES, page_bytes);
    let reserved_pages = div_ceil(reserved_bytes, page_bytes);
    let available = saveable_pages.saturating_add(free_pages);
    let max_image_pages = available.saturating_sub(metadata_pages.saturating_add(io_pages))
        / 2u64;
    let max_image_pages = max_image_pages.saturating_sub(reserved_pages.saturating_mul(2));
    let requested = div_ceil(image_bytes, page_bytes).min(max_image_pages);
    let minimum = saveable_pages.saturating_sub(reclaimable_pages).min(max_image_pages);
    let desired_pages = requested.max(minimum);
    Budget {
        desired_pages,
        reclaim_pages: saveable_pages.saturating_sub(desired_pages),
        max_image_pages,
        free_floor_pages: io_pages.saturating_add(reserved_pages),
    }
}

/// Bound the copy pool by current post-reclaim demand plus every allocation
/// which may become saveable before final allocator capture.  The transaction
/// metadata estimate is taken at the admission ceiling, so this one-pass
/// closure remains conservative without retaining the ceiling itself. # C: O(1)
pub fn retained_capacity(current_saveable: u64, metadata_at_ceiling: u64,
    allocation_headroom_pages: u64, max_image_pages: u64) -> Option<u64>
{
    current_saveable.checked_add(metadata_at_ceiling)
        .and_then(|capacity| capacity.checked_add(allocation_headroom_pages))
        .filter(|capacity| *capacity <= max_image_pages)
}

const fn div_ceil(value: u64, divisor: u64) -> u64 {
    if divisor == 0 { return u64::MAX; }
    value / divisor + ((value % divisor != 0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;

    #[test]
    fn requested_image_drives_reclaim_above_the_real_minimum() {
        let budget = calculate(6000, 6000, 8, 4000, 3000 * PAGE, 0, PAGE);
        assert_eq!(budget.desired_pages, 3000);
        assert_eq!(budget.reclaim_pages, 3000);
        assert!(budget.max_image_pages >= budget.desired_pages);
    }

    #[test]
    fn unreclaimable_population_is_the_best_effort_lower_bound() {
        let budget = calculate(6000, 6000, 8, 1000, PAGE, 0, PAGE);
        assert_eq!(budget.desired_pages, 5000);
        assert_eq!(budget.reclaim_pages, 1000);
    }

    #[test]
    fn reserved_bytes_reduce_the_image_ceiling_and_raise_the_free_floor() {
        let plain = calculate(4000, 6000, 0, 0, u64::MAX, 0, PAGE);
        let reserved = calculate(4000, 6000, 0, 0, u64::MAX, 11 * PAGE, PAGE);
        assert_eq!(plain.max_image_pages - reserved.max_image_pages, 22);
        assert_eq!(reserved.free_floor_pages - plain.free_floor_pages, 11);
    }

    #[test]
    fn impossible_reserve_saturates_to_an_empty_image_budget() {
        let budget = calculate(10, 10, 10, 10, 0, u64::MAX, PAGE);
        assert_eq!(budget.max_image_pages, 0);
        assert_eq!(budget.desired_pages, 0);
        assert_eq!(budget.reclaim_pages, 10);
    }

    #[test]
    fn retained_pool_tracks_post_reclaim_demand_not_admission_ceiling() {
        let max = 1u64 << 19;
        let current = 24_000;
        let metadata = 7_000;
        let retained = retained_capacity(current, metadata, 1_280, max).unwrap();
        assert_eq!(retained, 32_280);
        assert!(retained < max / 10,
            "a small live image must not retain the half-memory ceiling");
        assert_eq!(retained_capacity(current + 1, metadata, 1_280, max), Some(retained + 1),
            "post-reclaim live demand must remain the retained-pool owner");
    }

    #[test]
    fn retained_pool_includes_conservative_future_metadata_and_enforces_ceiling() {
        assert_eq!(retained_capacity(100, 17, 0, 117), Some(117));
        assert_eq!(retained_capacity(100, 18, 0, 117), None,
            "metadata growth beyond the admitted ceiling must fail closed");
        assert_eq!(retained_capacity(u64::MAX, 1, 0, u64::MAX), None);
    }

    #[test]
    fn io_and_driver_reserve_are_retained_for_post_preallocation_growth() {
        let budget = calculate(20_000, 30_000, 100, 0, u64::MAX, 256 * PAGE, PAGE);
        assert_eq!(budget.free_floor_pages, 1_280);
        assert_eq!(retained_capacity(8_000, 2_000, budget.free_floor_pages,
            budget.max_image_pages), Some(11_280));
    }

    #[test]
    fn measured_closure_repeats_when_its_own_backing_grows() {
        let floor = 17;
        let first = retained_capacity(100, 0, floor, 1_000).unwrap();
        assert_eq!(first, 117);
        let after_backing_growth = retained_capacity(113, 0, floor, 1_000).unwrap();
        assert_eq!(after_backing_growth, 130);
        assert_eq!(retained_capacity(113, 0, floor, 1_000), Some(after_backing_growth),
            "closure is stable only after a post-growth allocator measurement");
    }
}
