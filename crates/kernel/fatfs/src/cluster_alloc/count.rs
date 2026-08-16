//! Establishing how many clusters are free.
//!
//! FAT keeps no free-space accounting of its own beyond the FAT32 information
//! sector's hint, so the only authoritative answer is a scan of the whole
//! table. The reference scans once, on the first question that needs the
//! answer, and maintains the total from then on — which is why `statfs` on a
//! freshly mounted volume is O(table) and every later one is free.

use crate::chain::{self, Link};
use crate::fsinfo::FreeState;
use crate::geometry::{Geometry, FAT_START_ENT};

/// Free clusters on this volume, by scanning. # C: O(total clusters)
pub fn count_free(geo: &Geometry, table: &[u8]) -> u32 {
    let mut free = 0;
    for cluster in FAT_START_ENT..geo.max_cluster {
        if chain::read_entry(geo.width, table, cluster) == Some(Link::Free) { free += 1; }
    }
    free
}

/// The volume's free-cluster count, scanning only when the stored one cannot
/// be acted on.
///
/// A count that is merely present is not enough: it must also be trusted, and
/// a count read from an information sector is not until the mount says so.
/// Once derived here it is both, and is marked for write-back so the next
/// mount can start from it.
/// # C: O(total clusters) on the first call, O(1) after
pub fn count_free_clusters(geo: &Geometry, table: &[u8], st: &mut FreeState) -> u32 {
    if let Some(free) = st.trusted_count() { return free; }
    let free = count_free(geo, table);
    st.set_counted(free);
    free
}
