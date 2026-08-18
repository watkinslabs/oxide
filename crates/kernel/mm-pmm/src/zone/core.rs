//! PMM resolution of `kernelcore=` and `movablecore=` requests.

use cmdline::memory::{CoreValue, memory_core_request};
use super::{PAGEBLOCK_PAGES, ZoneLimits};

fn pages(value: CoreValue, total_pages: u64, page_bytes: u64) -> Option<u64> {
    match value {
        CoreValue::Bytes(bytes) => Some(bytes / page_bytes),
        CoreValue::Percent(percent) => Some(total_pages.saturating_mul(percent).saturating_div(100)),
        CoreValue::Mirror => None,
    }
}

fn round_up(value: u64, unit: u64) -> u64 {
    value.checked_add(unit - 1).map(|end| (end / unit) * unit).unwrap_or(u64::MAX)
}

/// Apply the command line's movable-core request to architecture defaults.
/// The movable tail begins no lower than the highest ordinary zone boundary,
/// so a DMA-capable range is never silently converted into movable-only RAM.
/// # C: O(line length)
pub fn apply_memory_core_request(mut limits: ZoneLimits, line: &[u8], pfn_max: u64, page_bytes: u64) -> ZoneLimits {
    let request = memory_core_request(line);
    if request.kernelcore == Some(CoreValue::Mirror) { return limits; }
    let mut kernelcore = request.kernelcore.and_then(|value| pages(value, pfn_max, page_bytes)).unwrap_or(0);
    if let Some(movablecore) = request.movablecore.and_then(|value| pages(value, pfn_max, page_bytes)) {
        let movablecore = round_up(movablecore, PAGEBLOCK_PAGES).min(pfn_max);
        kernelcore = kernelcore.max(pfn_max.saturating_sub(movablecore));
    }
    if kernelcore == 0 || kernelcore >= pfn_max { return limits; }
    let ordinary_floor = limits.dma_end_pfn.max(limits.dma32_end_pfn).min(pfn_max);
    let start = round_up(kernelcore.max(ordinary_floor), PAGEBLOCK_PAGES).min(pfn_max);
    if start < pfn_max { limits.movable_start_pfn = Some(start); }
    limits
}
