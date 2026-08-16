//! Which newly claimed clusters must be zeroed before use.
//!
//! Not all of them, and the asymmetry is deliberate in the reference. A
//! DIRECTORY cluster is zeroed the moment it is claimed, because a directory
//! is read to its end and a zero first name byte is what says "no more entries
//! follow" — an unzeroed cluster makes whatever the medium last held there
//! read back as file names. A FILE's cluster is not zeroed: nothing reads past
//! the size in the directory record, so the stale bytes are unreachable, and
//! zeroing every claimed cluster would double the write cost of growing a file.

use crate::geometry::Geometry;

/// What a freshly claimed cluster is about to hold.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NewCluster {
    /// A file's data. Read only as far as the record's size, so its previous
    /// contents are unreachable.
    File,
    /// Directory entries. Read to the first zero name byte, so its previous
    /// contents ARE reachable and must not be there.
    Directory,
}

impl NewCluster {
    /// Whether this cluster's bytes must be cleared before anything reads it.
    /// # C: O(1)
    pub fn must_zero(self) -> bool { self == NewCluster::Directory }
}

/// The sectors a caller must clear for a newly claimed cluster, as a first
/// sector and a count. `None` when this cluster needs no clearing, or names no
/// data on this volume.
/// # C: O(1)
pub fn zero_range(geo: &Geometry, cluster: u32, kind: NewCluster) -> Option<(u32, u32)> {
    if !kind.must_zero() { return None; }
    Some((geo.cluster_sector(cluster)?, geo.sec_per_clus))
}
