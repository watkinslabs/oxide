use super::*;
use crate::kassert;
use crate::watermark::ZoneWatermarks;
use crate::zone::{lowmem_reserve, zone_watermark_ok, AllocWmark, LowmemReserve, ZoneLayout, ZoneLimits, ZoneType, Zonelist, DEFAULT_LOWMEM_RESERVE_RATIO, NR_ZONES};

// Module manifest:
//   `api.rs`        — the `Pmm` owner struct plus the allocate / free / query
//                     surface; the split-and-coalesce paths live here.
//   `construct.rs`  — construction: zone partition, region seeding, derived state.
//   `zones.rs`      — per-zone watermarks and the statistics rows.
//   `reserve.rs`    — permanent boot-path reservations.
//   `inner.rs`      — lock-protected state and the free-list primitives.
//   `accounting.rs` — the observation structs the query surface returns.
//   `audit.rs`      — invariant walk.
//   `free_node.rs`  — the intrusive free-node header layout.
//   `double_free.rs`, `poison.rs` — debug-feature detectors.

mod api;
mod construct;
mod zones;
mod reserve;
mod accounting;
mod audit;
mod double_free;
mod free_node;
mod inner;
#[cfg(any(test, feature = "debug-watchdog", feature = "debug-cow"))]
mod poison;

pub use api::Pmm;
pub use accounting::{PmmSnapshot, ZoneStat};
#[cfg(test)]
pub(crate) const TEST_FREE_NODE_NEXT_OFF: usize = free_node::OFF_NEXT;
#[cfg(test)]
pub(crate) const TEST_FREE_NODE_PREV_OFF: usize = free_node::OFF_PREV;
#[cfg(all(test, feature = "debug-watchdog"))]
pub(crate) use poison::take_test_mismatch;
