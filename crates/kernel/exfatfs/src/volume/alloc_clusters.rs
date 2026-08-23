//! Claiming, extending and releasing clusters.
//!
//! Allocation reads the BITMAP, never the table. On this filesystem a
//! contiguous run has no table entries, so every one of its clusters reads as
//! free from the table and allocating from it hands out clusters that are
//! already in use.
//!
//! The other rule this module owns is the one that makes `NoFatChain` safe: a
//! run may stay flagged contiguous only while the clusters it gains are the
//! ones immediately after it. The first time they are not, the run's table
//! entries are written for the first time and the flag flips — before the new
//! cluster is linked, never after.

use syscall::errno::Errno;

use sectors::SectorSource;
use alloc::vec::Vec;

use crate::chain::Chain;
use crate::fat;
use crate::uapi::{ALLOC_FAT_CHAIN, ALLOC_NO_FAT_CHAIN, EOF_CLUSTER, FIRST_CLUSTER};

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Clusters this volume has free. # C: O(1)
    pub fn free_clusters(&self) -> u32 { self.geo.data_clusters().saturating_sub(self.used_clusters) }

    /// Clusters in use. # C: O(1)
    pub fn used_clusters(&self) -> u32 { self.used_clusters }

    /// Write the bitmap sector holding `cluster`'s bit back to the medium.
    /// # C: O(sector bytes)
    fn flush_bitmap_bit(&self, cluster: u32) -> Result<(), Errno> {
        let sector = self.bitmap.sector_index(cluster, self.geo.sector_bits).ok_or(Errno::Eio)?;
        let bytes = self.bitmap.sector_bytes(sector, self.geo.sector_size).ok_or(Errno::Eio)?;
        let offset = sector * u64::from(self.geo.sector_size);
        self.write_at(&self.bitmap_chain, offset, bytes)
    }

    /// Write the table sector holding `cluster`'s entry back, to every copy of
    /// the table the volume carries.
    ///
    /// Both copies or neither: a volume whose two tables disagree is one where
    /// a repair tool has to choose, and choosing wrongly loses a file.
    /// # C: O(sector bytes)
    fn flush_fat_entry(&self, cluster: u32) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let bytes = self.fat.sector_bytes(&self.geo, cluster).ok_or(Errno::Eio)?;
        let (primary, mirror) = self.geo.fat_sector_of(cluster);
        self.source.write_sectors(primary, bytes)?;
        if mirror != primary { self.source.write_sectors(mirror, bytes)?; }
        Ok(())
    }

    /// Set one table entry, on the medium and in the copy every walk reads.
    /// # C: O(sector bytes)
    pub(crate) fn set_fat(&mut self, cluster: u32, value: u32) -> Result<(), Errno> {
        self.fat.set(cluster, value)?;
        self.flush_fat_entry(cluster)
    }

    /// Claim one cluster. # C: O(sector bytes)
    fn claim(&mut self, cluster: u32) -> Result<(), Errno> {
        self.bitmap.set(cluster)?;
        self.used_clusters = self.used_clusters.saturating_add(1);
        self.flush_bitmap_bit(cluster)
    }

    /// Release one cluster. # C: O(sector bytes)
    fn release(&mut self, cluster: u32) -> Result<(), Errno> {
        self.bitmap.clear(cluster)?;
        self.used_clusters = self.used_clusters.saturating_sub(1);
        self.flush_bitmap_bit(cluster)
    }

    /// Discard adjacent freed clusters as one device request, as the Linux
    /// exFAT allocator does. Discard is an optimization and a device may
    /// reject it after mount, so only EOPNOTSUPP changes the mount option;
    /// freeing the clusters remains successful for every other result too.
    /// # C: O(number of contiguous runs)
    fn discard_clusters(&mut self, clusters: &[u32]) {
        if !self.opts.discard || clusters.is_empty() { return; }
        let mut start = clusters[0];
        let mut count = 1u32;
        for &cluster in &clusters[1..] {
            if cluster == start.saturating_add(count) {
                count = count.saturating_add(1);
            } else {
                self.discard_run(start, count);
                if !self.opts.discard { return; }
                start = cluster;
                count = 1;
            }
        }
        self.discard_run(start, count);
    }

    /// Tell the medium to forget one contiguous cluster run.
    /// # C: O(1)
    fn discard_run(&mut self, start: u32, count: u32) {
        let Some(sector) = self.geo.cluster_sector(start) else { return; };
        let sectors = u64::from(count).saturating_mul(u64::from(self.geo.sectors_per_cluster));
        match self.source.discard_sectors(sector, sectors) {
            Ok(()) => {},
            Err(Errno::Eopnotsupp) => self.opts.discard = false,
            Err(_) => {},
        }
    }

    /// Write out the table entries a contiguous run never had, and flip it to
    /// chained.
    ///
    /// Called at the moment a run stops being able to grow in place. Doing it
    /// afterwards leaves a window in which the run is flagged contiguous but
    /// is not, and a reader in that window reads the wrong clusters.
    /// # C: O(run length * sector bytes)
    fn materialise_chain(&mut self, chain: &mut Chain) -> Result<(), Errno> {
        if !chain.contiguous() || chain.is_empty() {
            chain.flags = ALLOC_FAT_CHAIN;
            return Ok(());
        }
        fat::write_contiguous_chain(&mut self.fat, chain.dir, chain.size)?;
        for i in 0..chain.size {
            self.flush_fat_entry(chain.dir + i)?;
        }
        chain.flags = ALLOC_FAT_CHAIN;
        Ok(())
    }

    /// Extend `chain` by `count` clusters.
    ///
    /// The run keeps its contiguous flag exactly while every cluster it gains
    /// follows the last one it had. `contiguous_only` refuses to break that —
    /// which is what a caller that needs one extent asks for.
    /// # C: O(count * volume clusters) worst case
    pub fn alloc_clusters(&mut self, chain: &mut Chain, count: u32, contiguous_only: bool)
        -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        if count == 0 { return Ok(()); }
        if count > self.free_clusters() { return Err(Errno::Enospc); }

        // A run being started from nothing begins wherever the hint points; an
        // existing one prefers the cluster after its last, so a growing file
        // stays one extent for as long as the volume allows.
        let mut want = if chain.is_empty() { self.hint }
                       else { chain::last_of(self, chain)?.saturating_add(1) };
        if !self.geo.valid_cluster(want) { want = FIRST_CLUSTER; }

        let mut claimed = 0u32;
        let mut last = if chain.is_empty() { EOF_CLUSTER } else { chain::last_of(self, chain)? };
        while claimed < count {
            let Some(found) = self.bitmap.find_free(want) else {
                self.unwind(chain, claimed)?;
                return Err(Errno::Enospc);
            };
            let breaks_run = found != want;
            if breaks_run && !chain.is_empty() {
                if contiguous_only { self.unwind(chain, claimed)?; return Err(Errno::Enospc); }
                if chain.contiguous() { self.materialise_chain(chain)?; }
            }
            self.claim(found)?;
            if chain.is_empty() {
                chain.dir = found;
                // A run of one cluster is trivially contiguous, and stays so
                // until something forces it apart.
                chain.flags = ALLOC_NO_FAT_CHAIN;
            } else if !chain.contiguous() {
                self.set_fat(last, found)?;
                self.set_fat(found, EOF_CLUSTER)?;
            }
            chain.size += 1;
            claimed += 1;
            last = found;
            want = found.saturating_add(1);
            if !self.geo.valid_cluster(want) {
                // Wrapping to the front of the heap can no longer extend a
                // contiguous run, so it becomes a chained one first.
                if chain.contiguous() && claimed < count {
                    if contiguous_only { self.unwind(chain, claimed)?; return Err(Errno::Enospc); }
                    self.materialise_chain(chain)?;
                }
                want = FIRST_CLUSTER;
            }
        }
        self.hint = last;
        Ok(())
    }

    /// Give back the clusters an allocation had claimed before it failed.
    ///
    /// A failed allocation that leaves its clusters claimed loses them until
    /// the next repair: nothing references them and the bitmap says they are
    /// in use.
    /// # C: O(claimed)
    fn unwind(&mut self, chain: &mut Chain, claimed: u32) -> Result<(), Errno> {
        if claimed == 0 { return Ok(()); }
        let clusters = crate::chain::walk(&self.geo, &self.fat_reader(), chain)?;
        let start = clusters.len().saturating_sub(claimed as usize);
        let released = clusters[start..].to_vec();
        for cluster in &released {
            self.release(*cluster)?;
        }
        self.discard_clusters(&released);
        chain.size -= claimed;
        if chain.size == 0 { *chain = Chain::empty(); }
        Ok(())
    }

    /// Release every cluster of a run. # C: O(run length)
    pub fn free_chain(&mut self, chain: &Chain) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        if chain.is_empty() { return Ok(()); }
        let clusters: Vec<u32> = crate::chain::walk(&self.geo, &self.fat_reader(), chain)?;
        for cluster in &clusters {
            // The table entry is cleared as well as the bit. A freed cluster
            // whose entry still points somewhere is what a repair tool reads
            // as a cross-link.
            if !chain.contiguous() { self.set_fat(*cluster, 0)?; }
            self.release(*cluster)?;
        }
        self.discard_clusters(&clusters);
        Ok(())
    }

    /// Shorten a run to `keep` clusters, releasing the rest. # C: O(run length)
    pub fn truncate_chain(&mut self, chain: &mut Chain, keep: u32) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        if keep >= chain.size { return Ok(()); }
        let clusters = crate::chain::walk(&self.geo, &self.fat_reader(), chain)?;
        let released = clusters[keep as usize..].to_vec();
        for cluster in &released {
            if !chain.contiguous() { self.set_fat(*cluster, 0)?; }
            self.release(*cluster)?;
        }
        self.discard_clusters(&released);
        if keep == 0 {
            *chain = Chain::empty();
            return Ok(());
        }
        if !chain.contiguous() { self.set_fat(clusters[keep as usize - 1], EOF_CLUSTER)?; }
        chain.size = keep;
        Ok(())
    }

    /// Fill a cluster with zeros, which every new directory cluster needs:
    /// an entry byte left over from the cluster's last owner reads as a name.
    /// # C: O(cluster bytes)
    pub(crate) fn zero_cluster(&self, cluster: u32) -> Result<(), Errno> {
        let per = usize::try_from(self.geo.cluster_bytes()).map_err(|_| Errno::Einval)?;
        self.write_cluster(cluster, &alloc::vec![0u8; per])
    }
}

/// The last cluster of a run, as a free function so the borrow of `self` ends
/// before the caller mutates it. # C: O(run length)
mod chain {
    use super::*;

    /// # C: O(run length)
    pub fn last_of<S: SectorSource>(vol: &Volume<S>, chain: &Chain) -> Result<u32, Errno> {
        crate::chain::last_cluster(&vol.geo, &vol.fat_reader(), chain)
    }
}
