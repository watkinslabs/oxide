//! Where everything on the volume lives, once the boot sector's fields are
//! resolved against each other.
//!
//! Every number here is derived, never re-read: a caller that recomputes a
//! sector from the boot sector's shift counts will eventually disagree with
//! one that did the arithmetic differently.

use crate::boot::Boot;
use crate::uapi::{DENTRY_BITS, FAT_ENTRY_BYTES, FIRST_CLUSTER, RESERVED_CLUSTERS};

/// The resolved layout of a mounted volume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Geometry {
    pub sector_size: u32,
    pub sector_bits: u8,
    pub sectors_per_cluster: u32,
    pub cluster_bits: u8,
    /// First sector of the first allocation table.
    pub fat_start: u32,
    /// First sector of the second table, equal to the first when there is one.
    pub fat_mirror_start: u32,
    pub fat_sectors: u32,
    pub fats: u8,
    /// First sector of the cluster heap.
    pub data_start: u32,
    /// Clusters the volume has, the two reserved ones included.
    pub num_clusters: u32,
    pub root_cluster: u32,
    pub total_sectors: u64,
    pub serial: u32,
}

/// Resolve a boot sector into a layout. # C: O(1)
pub fn resolve(boot: &Boot) -> Geometry {
    let sector_size = 1u32 << boot.sect_size_bits;
    let cluster_bits = boot.sect_per_clus_bits + boot.sect_size_bits;
    let fat_mirror_start = if boot.num_fats == 2 { boot.fat_offset + boot.fat_length }
                           else { boot.fat_offset };
    Geometry {
        sector_size,
        sector_bits: boot.sect_size_bits,
        sectors_per_cluster: 1u32 << boot.sect_per_clus_bits,
        cluster_bits,
        fat_start: boot.fat_offset,
        fat_mirror_start,
        fat_sectors: boot.fat_length,
        fats: boot.num_fats,
        data_start: boot.clu_offset,
        num_clusters: boot.clu_count.saturating_add(RESERVED_CLUSTERS),
        root_cluster: boot.root_cluster,
        total_sectors: boot.vol_length,
        serial: boot.vol_serial,
    }
}

impl Geometry {
    /// Bytes in one cluster. # C: O(1)
    pub fn cluster_bytes(&self) -> u64 { 1u64 << self.cluster_bits }

    /// Directory entries one cluster holds. # C: O(1)
    pub fn dentries_per_cluster(&self) -> u32 { 1u32 << (u32::from(self.cluster_bits) - DENTRY_BITS) }

    /// Clusters usable for data — the two reserved ones are not. # C: O(1)
    pub fn data_clusters(&self) -> u32 { self.num_clusters.saturating_sub(RESERVED_CLUSTERS) }

    /// Whether `cluster` names a cluster this volume has. # C: O(1)
    pub fn valid_cluster(&self, cluster: u32) -> bool {
        cluster >= FIRST_CLUSTER && cluster < self.num_clusters
    }

    /// First sector of a cluster, or `None` when it is not a cluster of this
    /// volume. # C: O(1)
    pub fn cluster_sector(&self, cluster: u32) -> Option<u64> {
        if !self.valid_cluster(cluster) { return None; }
        let index = u64::from(cluster - FIRST_CLUSTER);
        Some(u64::from(self.data_start) + index * u64::from(self.sectors_per_cluster))
    }

    /// Byte offset of a cluster from the start of the volume. # C: O(1)
    pub fn cluster_offset(&self, cluster: u32) -> Option<u64> {
        Some(self.cluster_sector(cluster)? << self.sector_bits)
    }

    /// Sector holding the table entry for `cluster`, in each copy of the
    /// table. # C: O(1)
    pub fn fat_sector_of(&self, cluster: u32) -> (u64, u64) {
        let byte = u64::from(cluster) * FAT_ENTRY_BYTES as u64;
        let within = byte >> self.sector_bits;
        (u64::from(self.fat_start) + within, u64::from(self.fat_mirror_start) + within)
    }

    /// Byte offset of a table entry within its sector. # C: O(1)
    pub fn fat_offset_in_sector(&self, cluster: u32) -> usize {
        let byte = u64::from(cluster) * FAT_ENTRY_BYTES as u64;
        (byte & (u64::from(self.sector_size) - 1)) as usize
    }

    /// Clusters needed to hold `bytes`. # C: O(1)
    pub fn clusters_for(&self, bytes: u64) -> u32 {
        let per = self.cluster_bytes();
        u32::try_from(bytes.div_ceil(per)).unwrap_or(u32::MAX)
    }

    /// The largest file this volume's cluster size admits. # C: O(1)
    pub fn max_bytes(&self) -> u64 {
        u64::from(crate::uapi::MAX_NUM_CLUSTER).saturating_mul(self.cluster_bytes())
    }
}

#[cfg(test)]
#[path = "tests/geometry.rs"]
mod tests;
