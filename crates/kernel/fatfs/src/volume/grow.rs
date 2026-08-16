//! Giving a directory another cluster, cleared before anything reads it.
//!
//! A directory is read to its first zero name byte, so a cluster joined to one
//! while still holding whatever the medium last had there does not extend the
//! directory — it fills it with names made of stale bytes, and a scan runs
//! past the real end into them. That is why `cluster_alloc::zero` says a
//! DIRECTORY cluster must be cleared and a file's need not, and this is the
//! caller that obeys it.
//!
//! The clearing happens BEFORE the cluster is linked in, so a reader that
//! reaches the directory between the two steps sees the directory as it was.

use alloc::vec;

use syscall::errno::Errno;

use crate::cluster_alloc::{alloc_clusters, chain_add, zero_range, NewCluster};
use crate::fatcache::{get_cluster, ChainCache, Seek, TO_EOF};

use super::{SectorSource, Volume};

impl<S: SectorSource> Volume<S> {
    /// Clear one cluster's sectors. # C: O(cluster bytes)
    pub(crate) fn zero_cluster(&self, cluster: u32) -> Result<(), Errno> {
        let (first, count) = zero_range(&self.geo, cluster, NewCluster::Directory)
            .ok_or(Errno::Eio)?;
        let bytes = usize::try_from(u64::from(count) * u64::from(self.geo.sector_size))
            .map_err(|_| Errno::Eio)?;
        self.source.write_sectors(u64::from(first), &vec![0u8; bytes])
    }

    /// Claim one cluster for a directory that does not exist yet, cleared and
    /// standing alone. # C: O(clusters scanned)
    pub(crate) fn new_directory_cluster(&mut self) -> Result<u32, Errno> {
        let got = alloc_clusters(&self.geo, &mut self.table, &mut self.free, 1)?;
        let cluster = got[0];
        self.zero_cluster(cluster)?;
        self.flush_table()?;
        self.flush_fsinfo()?;
        Ok(cluster)
    }

    /// Give an existing directory `count` more clusters.
    ///
    /// A fixed root cannot grow: its size is a field of the boot sector and
    /// the data area begins immediately after it, so there is nowhere for
    /// another entry to go. `ENOSPC` is what the reference reports, and it is
    /// the reason a FAT12 or FAT16 root fills up while the volume is nearly
    /// empty.
    /// # C: O(clusters scanned)
    pub(crate) fn grow_directory(&mut self, dir: Option<u32>, count: usize)
        -> Result<(), Errno> {
        let Some(first) = dir else { return Err(Errno::Enospc) };
        if count == 0 { return Ok(()); }
        let mut cache = ChainCache::new();
        let tail = match get_cluster(&self.geo, &self.table, &mut cache, first, TO_EOF)? {
            Seek::Eof { dclus, .. } | Seek::At { dclus, .. } => dclus,
        };
        let got = alloc_clusters(&self.geo, &mut self.table, &mut self.free, count)?;
        for cluster in got.iter() { self.zero_cluster(*cluster)?; }
        chain_add(&self.geo, &mut self.table, &mut self.free, &got, tail)?;
        self.flush_table()?;
        self.flush_fsinfo()
    }
}
