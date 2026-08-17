//! Buddy-owned physical-memory accounting snapshots.
//!
//! The buddy lock is the sole serialization point for both allocation state
//! and these counters.  Values here are observations of real transitions, not
//! a second allocator state or a procfs-oriented reconstruction.

/// Atomic snapshot of the PMM-owned physical page domain.
///
/// `managed_pages` is the sum of usable ranges admitted at boot.  It excludes
/// holes in the raw PFN span.  `allocated_pages` excludes permanently reserved
/// boot pages, which remain separately visible in `reserved_pages`.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PmmSnapshot {
    pub managed_pages: u64,
    pub free_pages: u64,
    pub allocated_pages: u64,
    pub reserved_pages: u64,
    pub alloc_events: u64,
    pub alloc_event_pages: u64,
    pub free_events: u64,
    pub free_event_pages: u64,
}

/// Per-zone observation. `spanned_pages` counts the zone's whole PFN range,
/// holes included; `present_pages` counts only what the firmware map made
/// usable; `managed_pages` counts what actually reached the buddy lists.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZoneStat {
    pub zone: super::ZoneType,
    pub start_pfn: u64,
    pub spanned_pages: u64,
    pub present_pages: u64,
    pub managed_pages: u64,
    pub free_pages: u64,
    pub free_orders: [u64; crate::ORDERS],
    pub wmark: crate::watermark::ZoneWatermarks,
    pub lowmem_reserve: [u64; super::NR_ZONES],
}

impl ZoneStat {
    /// All-zero row for a zone slot that holds no memory. # C: O(1)
    pub const EMPTY: Self = Self {
        zone: super::ZoneType::Dma,
        start_pfn: 0,
        spanned_pages: 0,
        present_pages: 0,
        managed_pages: 0,
        free_pages: 0,
        free_orders: [0; crate::ORDERS],
        wmark: crate::watermark::ZoneWatermarks { min: 0, low: 0, high: 0, promo: 0 },
        lowmem_reserve: [0; super::NR_ZONES],
    };
}
