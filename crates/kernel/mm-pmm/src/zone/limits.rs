//! Zone boundary derivation. Boundaries are cumulative upper bounds in PFN:
//! zone `i` spans `[end(i-1), end(i))`, so a boundary that lands below an
//! earlier one simply leaves its zone empty rather than inverting the order.
//!
//! The numbers come from the platform, not from this file: on x86_64 the ISA
//! bus master limit and the 32-bit addressing limit; on aarch64 the firmware's
//! declared DMA constraint clamped to the 32-bit limit whenever RAM starts
//! below it, and in both cases clamped to the end of RAM.

use super::types::{ZoneType, NR_ZONES};

/// x86_64 ISA-era bus masters address 24 physical bits.
pub const X86_DMA_LIMIT_BYTES: u64 = 16 * 1024 * 1024;
/// A 32-bit DMA mask reaches this far and no further.
pub const DMA32_LIMIT_BYTES: u64 = 1u64 << 32;

/// Cumulative per-zone upper bounds, in PFN, exclusive.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZoneLimits {
    pub dma_end_pfn: u64,
    pub dma32_end_pfn: u64,
    /// First PFN handed to the movable zone. `None` leaves it empty, which is
    /// what a platform with no movable-core request gets.
    pub movable_start_pfn: Option<u64>,
}

/// Half-open PFN span of one zone.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ZoneSpan { pub start_pfn: u64, pub end_pfn: u64 }

impl ZoneSpan {
    /// Pages the span covers, holes included. # C: O(1)
    pub const fn spanned_pages(&self) -> u64 { self.end_pfn.saturating_sub(self.start_pfn) }
    /// Does the span contain any page at all? # C: O(1)
    pub const fn is_empty(&self) -> bool { self.end_pfn <= self.start_pfn }
    /// Is `pfn` inside the span? # C: O(1)
    pub const fn contains(&self, pfn: u64) -> bool { pfn >= self.start_pfn && pfn < self.end_pfn }
}

fn pfn_down(bytes: u64, page_bytes: u64) -> u64 { bytes / page_bytes }

impl ZoneLimits {
    /// x86_64 boundaries: the ISA limit and the 32-bit limit, each clamped to
    /// the end of RAM. # C: O(1)
    pub fn x86_64(pfn_max: u64, page_bytes: u64) -> Self {
        Self {
            dma_end_pfn: core::cmp::min(pfn_down(X86_DMA_LIMIT_BYTES, page_bytes), pfn_max),
            dma32_end_pfn: core::cmp::min(pfn_down(DMA32_LIMIT_BYTES, page_bytes), pfn_max),
            movable_start_pfn: None,
        }
    }

    /// aarch64 boundaries. `fw_dma_limit_bytes` is the most restrictive DMA
    /// constraint the firmware description declares, inclusive of its last
    /// addressable byte; absent, the platform is treated as unconstrained and
    /// the 32-bit limit is used instead whenever RAM reaches below it.
    /// # C: O(1)
    pub fn aarch64(fw_dma_limit_bytes: Option<u64>, dram_start_bytes: u64, pfn_max: u64, page_bytes: u64) -> Self {
        let dma32_end = core::cmp::min(pfn_down(DMA32_LIMIT_BYTES, page_bytes), pfn_max);
        // A device description constrains the bus; individual devices may be
        // narrower still, and platforms with RAM below the 32-bit line keep a
        // low DMA zone so those devices have somewhere to allocate from.
        let mut limit = fw_dma_limit_bytes.unwrap_or(u64::MAX);
        if dram_start_bytes < DMA32_LIMIT_BYTES { limit = core::cmp::min(limit, DMA32_LIMIT_BYTES - 1); }
        let dma_end = if limit == u64::MAX { pfn_max } else { core::cmp::min(pfn_down(limit, page_bytes) + 1, pfn_max) };
        Self { dma_end_pfn: dma_end, dma32_end_pfn: dma32_end, movable_start_pfn: None }
    }

    /// Boundaries for the arch this kernel is built for. # C: O(1)
    #[cfg(target_arch = "aarch64")]
    pub fn arch_default(pfn_max: u64, page_bytes: u64) -> Self { Self::aarch64(None, 0, pfn_max, page_bytes) }

    /// Boundaries for the arch this kernel is built for. Hosted builds use the
    /// x86_64 derivation so a hosted fixture reproduces a real zone split.
    /// # C: O(1)
    #[cfg(not(target_arch = "aarch64"))]
    pub fn arch_default(pfn_max: u64, page_bytes: u64) -> Self { Self::x86_64(pfn_max, page_bytes) }
}

/// The resolved PFN partition. Spans are contiguous, non-overlapping, in
/// address order, and together cover `[0, pfn_max)`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZoneLayout { spans: [ZoneSpan; NR_ZONES] }

impl Default for ZoneLayout {
    fn default() -> Self { Self { spans: [ZoneSpan::default(); NR_ZONES] } }
}

impl ZoneLayout {
    /// Resolve cumulative limits into spans. A limit below the running
    /// boundary yields an empty zone; every limit is clamped to `pfn_max` so
    /// the partition never claims memory that does not exist. # C: O(NR_ZONES)
    pub fn new(limits: ZoneLimits, pfn_max: u64) -> Self {
        let mut spans = [ZoneSpan::default(); NR_ZONES];
        let mut cur = 0u64;
        let movable_start = limits.movable_start_pfn
            .and_then(|start| start.checked_add(super::PAGEBLOCK_PAGES - 1).map(|end| (end / super::PAGEBLOCK_PAGES) * super::PAGEBLOCK_PAGES))
            .unwrap_or(pfn_max).min(pfn_max);
        // Movable, when requested, takes the tail; the addressable zones are
        // capped below it so no page belongs to two zones.
        let caps = [
            limits.dma_end_pfn.min(pfn_max).min(movable_start),
            limits.dma32_end_pfn.min(pfn_max).min(movable_start),
            movable_start,
            pfn_max,
        ];
        for (i, cap) in caps.iter().enumerate() {
            let end = if *cap > cur { *cap } else { cur };
            spans[i] = ZoneSpan { start_pfn: cur, end_pfn: end };
            cur = end;
        }
        Self { spans }
    }

    /// Single-zone layout: everything is normal memory. Used by fixtures that
    /// deliberately exercise the no-constraint path. # C: O(1)
    pub fn single_normal(pfn_max: u64) -> Self {
        Self::new(ZoneLimits { dma_end_pfn: 0, dma32_end_pfn: 0, movable_start_pfn: None }, pfn_max)
    }

    /// Span of `zone`. # C: O(1)
    pub const fn span(&self, zone: ZoneType) -> ZoneSpan { self.spans[zone as usize] }

    /// Span by index. # C: O(1)
    pub const fn span_at(&self, idx: usize) -> ZoneSpan { self.spans[idx] }

    /// Zone owning `pfn`. Every PFN below the layout's top belongs to exactly
    /// one zone; a PFN at or above it belongs to none. # C: O(NR_ZONES)
    pub fn zone_of(&self, pfn: u64) -> Option<ZoneType> {
        let mut i = 0;
        while i < NR_ZONES {
            if self.spans[i].contains(pfn) { return ZoneType::from_index(i); }
            i += 1;
        }
        None
    }

    /// Zone index owning `pfn`, or `NR_ZONES` when out of range. Cheaper than
    /// `zone_of` at the allocator's hot call sites. # C: O(NR_ZONES)
    pub fn index_of(&self, pfn: u64) -> usize {
        let mut i = 0;
        while i < NR_ZONES {
            if self.spans[i].contains(pfn) { return i; }
            i += 1;
        }
        NR_ZONES
    }

    /// Highest PFN the layout covers. # C: O(1)
    pub const fn pfn_max(&self) -> u64 { self.spans[NR_ZONES - 1].end_pfn }
}
