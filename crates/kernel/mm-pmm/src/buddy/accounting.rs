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
