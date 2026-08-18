//! Memory zones — the bounded-address partition of the buddy allocator.
//
// Module manifest:
//   `zone/types.rs`    — `ZoneType`, zone count, zone names.
//   `zone/gfp.rs`      — allocation-flag zone bits and the flag→zone map.
//   `zone/dma.rs`      — bus-master address bound resolved to zone bits.
//   `zone/limits.rs`   — per-arch zone boundary derivation + PFN→zone lookup.
//   `zone/core.rs`     — command-line movable-core resolution.
//   `zone/migrate.rs`  — GFP mobility class and fallback order.
//   `zone/zonelist.rs` — populated-zone fallback order and its walk.
//   `zone/reserve.rs`  — lowmem reserve, the per-zone floor a fallback-capable
//                        allocation class must leave behind.
//   `zone/wmark.rs`    — per-zone min/low/high and the allocation gate.
//   `zone/tests/`      — hosted tests; provenance for the verified contract.

mod types;
mod gfp;
mod dma;
mod limits;
mod core;
mod migrate;
mod zonelist;
mod reserve;
mod wmark;

pub use types::{ZoneType, NR_ZONES};
pub use dma::{gfp_for_pfn_limit, narrow_zone_bits};
pub use gfp::{gfp_zone, grants_min_reserve, GfpError, GFP_ATOMIC, GFP_DMA, GFP_DMA32, GFP_HIGH, GFP_HIGHMEM, GFP_KSWAPD_RECLAIM, GFP_MOVABLE, GFP_RECLAIMABLE, GFP_ZONEMASK};
pub use limits::{ZoneLayout, ZoneLimits, ZoneSpan};
pub use core::apply_memory_core_request;
pub use migrate::{gfp_migratetype, MigrateType, MIGRATE_TYPES, PAGEBLOCK_ORDER, PAGEBLOCK_PAGES};
pub use zonelist::Zonelist;
pub use reserve::{lowmem_reserve, LowmemReserve, DEFAULT_LOWMEM_RESERVE_RATIO};
pub use wmark::{slowpath_wmark, zone_watermark_ok, zone_watermark_ok_pages, AllocWmark, ZoneFreeArea};

#[cfg(test)]
#[path = "zone/tests.rs"]
mod tests;
