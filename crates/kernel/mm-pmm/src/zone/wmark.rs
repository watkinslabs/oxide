//! The per-zone allocation gate. A zone may serve an allocation only when the
//! free pages it would still hold afterwards clear its watermark plus the
//! reserve it owes to the narrower classes, and — for a high-order request —
//! only when a block of that order actually exists.

use super::reserve::LowmemReserve;
use super::types::{ZoneType, NR_ZONES};
use crate::ORDERS;

/// Which watermark an attempt is measured against, and how much of the min
/// reserve the calling context may dip into.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AllocWmark {
    /// First attempt: leave the low watermark intact.
    Low,
    /// Retry after the first attempt found nothing: the min watermark is the
    /// floor below which reclaim, not allocation, is the answer.
    Min,
    /// A caller that asked for the reserve and gets half of it.
    MinReserve,
    /// A caller that asked for the reserve AND cannot block, and so gets
    /// further into it than the reserve alone would allow.
    MinNonBlock,
}

/// Which rung of the min watermark a slowpath attempt is measured against.
///
/// The reserve discount is earned by asking for it, not by being unable to
/// block: a caller that cannot block but never asked is held to the whole
/// minimum, and only a caller holding both gets the deeper cut. Getting this
/// backwards is permissive — it lets an allocation that has not earned the
/// reserve drain what a blockable context is relying on. # C: O(1)
pub const fn slowpath_wmark(grants_min_reserve: bool, can_block: bool) -> AllocWmark {
    if !grants_min_reserve { return AllocWmark::Min; }
    if can_block { AllocWmark::MinReserve } else { AllocWmark::MinNonBlock }
}

/// Per-order free-block counts for one zone.
pub type ZoneFreeArea = [u64; ORDERS];

/// Free base pages the area represents. # C: O(ORDERS)
pub fn free_pages(area: &ZoneFreeArea) -> u64 {
    let mut sum = 0u64;
    for (o, n) in area.iter().enumerate() { sum = sum.saturating_add(n << o); }
    sum
}

fn effective_min(mark: u64, wmark: AllocWmark) -> u64 {
    match wmark {
        AllocWmark::Low | AllocWmark::Min => mark,
        // Asking for the reserve buys half of it.
        AllocWmark::MinReserve => mark - mark / 2,
        // A non-blocking caller that also asked for the reserve gets a
        // further quarter of what the reserve discount left.
        AllocWmark::MinNonBlock => { let m = mark - mark / 2; m - m / 4 }
    }
}

/// Order-0 form of [`zone_watermark_ok`] for a pageset cache. The caller
/// supplies the zone's atomically maintained total free-page count, which
/// includes pages held outside the mergeable buddy free areas.
/// # C: O(1)
pub fn zone_watermark_ok_pages(mark: u64, wmark: AllocWmark, reserve: u64, free: u64) -> bool {
    free > effective_min(mark, wmark).saturating_add(reserve)
}

/// May `zone` serve an order-`order` allocation whose highest permitted zone
/// is `highest_zoneidx`? `mark` is the zone's watermark for `wmark`.
/// # C: O(ORDERS)
pub fn zone_watermark_ok(
    zone: ZoneType,
    order: u8,
    mark: u64,
    wmark: AllocWmark,
    reserve: &LowmemReserve,
    highest_zoneidx: usize,
    area: &ZoneFreeArea,
) -> bool {
    // Pages inside a block bigger than the request cannot all be handed out,
    // so they do not count toward clearing the watermark.
    let free = free_pages(area).saturating_sub((1u64 << order) - 1);
    let idx = if highest_zoneidx < NR_ZONES { highest_zoneidx } else { NR_ZONES - 1 };
    if !zone_watermark_ok_pages(mark, wmark, reserve[zone as usize][idx], free) { return false; }
    if order == 0 { return true; }
    // A base-page surplus does not imply the contiguity a high-order request
    // needs; require a block that can actually satisfy it.
    for o in (order as usize)..ORDERS { if area[o] > 0 { return true; } }
    false
}
