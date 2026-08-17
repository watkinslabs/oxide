//! Address bound → zone selection for a bus-master allocation.
//!
//! A DMA constraint arrives as an address the device cannot reach past. The
//! allocator does not take addresses: it takes a highest permitted zone, and
//! every gate below that point — the per-zone watermark, the lowmem reserve a
//! zone owes the classes narrower than it, the reclaim/kill retry — is indexed
//! by zone. Resolving the bound to zone bits once, here, is what lets a
//! bounded request take the ordinary allocation path instead of a second one
//! that would have to re-derive all of that against an address.
//!
//! Resolution is optimistic and is checked afterwards: the zone whose top the
//! bound falls at or below is tried first, and a block that still lands
//! outside the bound is returned and the request retried one zone lower. The
//! ladder terminates because it is three rungs long.

use super::gfp::{GFP_DMA, GFP_DMA32, GFP_ZONEMASK};
use super::limits::ZoneLayout;
use super::types::ZoneType;

/// Zone bits for an allocation whose whole span must lie below `limit_pfn`
/// (exclusive). A bound above every addressable zone's top names no zone and
/// allocates normally. # C: O(1)
pub fn gfp_for_pfn_limit(layout: &ZoneLayout, limit_pfn: u64) -> u32 {
    if limit_pfn <= layout.span(ZoneType::Dma).end_pfn { return GFP_DMA; }
    if limit_pfn <= layout.span(ZoneType::Dma32).end_pfn { return GFP_DMA32; }
    0
}

/// The next narrower zone selection after a block came back outside its
/// bound, or `None` once the narrowest zone has already been tried.
/// # C: O(1)
pub fn narrow_zone_bits(gfp: u32) -> Option<u32> {
    let rest = gfp & !GFP_ZONEMASK;
    if gfp & (GFP_DMA32 | GFP_DMA) == 0 { return Some(rest | GFP_DMA32); }
    if gfp & GFP_DMA == 0 { return Some(rest | GFP_DMA); }
    None
}
