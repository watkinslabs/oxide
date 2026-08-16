//! What one mount is holding in memory.
//!
//! Three figures, split by what makes them grow. The STATIC part is fixed at
//! mount by the volume's geometry — the segment table is one entry per
//! segment whether or not anything has been written. The CACHED part grows
//! with what the mount has touched and shrinks at a checkpoint. The PAGED
//! part is file and metadata contents held for their own sake.
//!
//! Every figure is computed from the structures that exist HERE, not from
//! the shapes another implementation would hold. A mount with no page cache
//! reports no paged bytes, and that zero is a fact about this build rather
//! than an unimplemented figure: the bytes are not held, so there are none to
//! report.

use core::mem::size_of;

use sectors::SectorSource;

use crate::summary::{NatEntry, SitEntry};
use crate::volume::Volume;

use super::counters::{extent_of, Counters};

/// The three figures, and the per-cache split the report breaks the cached
/// one down by.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Footprint {
    pub base_mem: u64,
    pub cache_mem: u64,
    pub page_mem: u64,
    pub ext_mem: [u64; extent_of::MAX],
}

impl Footprint {
    /// # C: O(1)
    pub fn total(&self) -> u64 { self.base_mem + self.cache_mem + self.page_mem }

    /// Measure a mount.
    ///
    /// The static part is derived from the geometry rather than remembered
    /// from the first call: it can change under an online resize, and a
    /// figure cached at mount would keep reporting the size the volume used
    /// to be.
    /// # C: O(1)
    pub fn of<S: SectorSource>(v: &Volume<S>, _c: &Counters) -> Footprint {
        let sb = v.super_block();
        let main_segs = u64::from(sb.segment_count_main);

        // Fixed by geometry: the superblock and checkpoint the mount parsed,
        // the checkpoint's own bytes it kept because the version bitmaps run
        // across blocks, both version bitmaps, the whole segment table, and
        // one open-log buffer per log.
        let mut base = size_of::<crate::sb::SuperBlock>() as u64
            + size_of::<crate::checkpoint::Checkpoint>() as u64
            + v.cp_raw.len() as u64
            + v.nat_bitmap.len() as u64
            + v.sit_bitmap.len() as u64;
        if v.sit.is_some() { base += main_segs * size_of::<SitEntry>() as u64; }
        for log in v.logs().iter() {
            base += size_of::<crate::volume::Curseg>() as u64 + log.sum.len() as u64;
        }

        // Grows with what the mount has touched.
        let nat = v.nat_dirty.len() as u64 * (size_of::<u32>() + size_of::<NatEntry>()) as u64;
        let nat_j = v.nat_journal.len() as u64 * (size_of::<u32>() + size_of::<NatEntry>()) as u64;
        let sit_j = v.sit_journal.len() as u64 * (size_of::<u32>() + size_of::<SitEntry>()) as u64;
        let sit_d = v.sit_dirty.len() as u64 * size_of::<u32>() as u64;
        let dq = v.dquots.len() as u64 * size_of::<crate::quota::Dqblk>() as u64;
        let dq_d = v.dq_dirty.len() as u64 * (2 * size_of::<u32>()) as u64;
        let orph = v.orphans.len() as u64 * size_of::<u32>() as u64;
        let opens = v.opens.len() as u64 * (2 * size_of::<u32>()) as u64;
        let disc = v.pending_discard.len() as u64 * size_of::<u32>() as u64;
        let prefree = u64::from(v.prefree_count()) * size_of::<u32>() as u64;
        let cache = nat + nat_j + sit_j + sit_d + dq + dq_d + orph + opens + disc + prefree;

        Footprint { base_mem: base, cache_mem: cache, page_mem: 0,
                    ext_mem: [0; extent_of::MAX] }
    }
}
