//! The mounted volume's free-cluster count and allocation hint.
//!
//! Three states, and the difference between the last two is the whole point:
//! the count can be UNKNOWN, KNOWN-BUT-UNTRUSTED, or KNOWN-AND-TRUSTED. A
//! count read from the information sector is known and untrusted, because the
//! system that wrote it may have died before it was right; it becomes trusted
//! only when the mount asked for it to be, or when this volume derived it
//! itself by scanning. Everything that reads the count — the fast `ENOSPC`
//! refusal, `statfs` — consults the trust bit, not just the value.

use crate::geometry::{Geometry, FAT_START_ENT};

use super::layout::{default_hint, FsInfo};

/// Free-cluster accounting for one mounted volume.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FreeState {
    free: Option<u32>,
    valid: bool,
    prev_free: u32,
    dirty: bool,
}

impl Default for FreeState {
    fn default() -> Self { Self::new() }
}

impl FreeState {
    /// A volume that has not looked at its information sector: count unknown,
    /// hint at the first data cluster. # C: O(1)
    pub fn new() -> Self {
        FreeState { free: None, valid: false, prev_free: default_hint(), dirty: false }
    }

    /// Take both counters from the information sector.
    ///
    /// `trust` is the mount's request that the stored count be believed.
    /// Without it the count is still recorded but must be re-derived before
    /// anything acts on it, because a volume unmounted uncleanly leaves a
    /// count that is merely plausible.
    /// # C: O(1)
    pub fn adopt(&mut self, info: &FsInfo, trust: bool) {
        if trust { self.valid = true; }
        self.free = info.free_clusters;
        if let Some(next) = info.next_cluster { self.prev_free = next; }
    }

    /// Apply the volume's own limits to whatever the sector claimed.
    ///
    /// A count larger than the volume has clusters is impossible, so it is
    /// discarded rather than clamped — a wrong number is worse than none. The
    /// hint is wrapped into range instead, because any cluster number is a
    /// legitimate place to start searching.
    /// # C: O(1)
    pub fn sanitize(&mut self, geo: &Geometry) {
        if let Some(free) = self.free {
            if free > geo.total_clusters { self.free = None; }
        }
        if geo.max_cluster != 0 { self.prev_free %= geo.max_cluster; }
        if self.prev_free < FAT_START_ENT { self.prev_free = FAT_START_ENT; }
    }

    /// Free clusters, when known. # C: O(1)
    pub fn free_clusters(&self) -> Option<u32> { self.free }

    /// Whether the count may be acted on without re-deriving it. # C: O(1)
    pub fn is_trusted(&self) -> bool { self.valid }

    /// The count, only when it can be acted on. # C: O(1)
    pub fn trusted_count(&self) -> Option<u32> { if self.valid { self.free } else { None } }

    /// Cluster the last allocation ended at; the next search starts after it.
    /// # C: O(1)
    pub fn hint(&self) -> u32 { self.prev_free }

    /// Whether the information sector needs rewriting. # C: O(1)
    pub fn is_dirty(&self) -> bool { self.dirty }

    /// # C: O(1)
    pub fn mark_dirty(&mut self) { self.dirty = true; }

    /// Called once the information sector has been written back. # C: O(1)
    pub fn clear_dirty(&mut self) { self.dirty = false; }

    /// Record a count this volume derived itself by scanning its own table.
    /// That count is trusted, having just been measured. # C: O(1)
    pub fn set_counted(&mut self, free: u32) {
        self.free = Some(free);
        self.valid = true;
        self.dirty = true;
    }

    /// One cluster was handed out: advance the hint and drop the count by one.
    ///
    /// The count moves only when it was known. A count that is unknown stays
    /// unknown rather than becoming a guess counted down from nothing.
    /// # C: O(1)
    pub fn took(&mut self, cluster: u32) {
        self.prev_free = cluster;
        if let Some(free) = self.free { self.free = Some(free.saturating_sub(1)); }
    }

    /// One cluster came back. # C: O(1)
    pub fn gave_back(&mut self) {
        if let Some(free) = self.free { self.free = Some(free + 1); self.dirty = true; }
    }

    /// A scan of the whole table found no more free clusters, so the count is
    /// zero and now known exactly. # C: O(1)
    pub fn exhausted(&mut self) { self.free = Some(0); self.valid = true; }

    /// Force the hint, for a caller restoring saved state. # C: O(1)
    pub fn set_hint(&mut self, cluster: u32) { self.prev_free = cluster; }
}
