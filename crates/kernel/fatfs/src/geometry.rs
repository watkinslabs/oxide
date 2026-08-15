//! Where everything on the volume lives, and how wide its table entries are.
//!
//! The width is NOT declared anywhere on a FAT12 or FAT16 volume. It is
//! derived from the number of data clusters, and the boundary is a specific
//! constant — get it wrong by one and every table entry after the first is
//! read at the wrong bit offset, which reads as corruption rather than as a
//! mount failure. That derivation is the reason this module exists.

use syscall::errno::Errno;

use crate::bpb::{Bpb, DIR_ENTRY_BYTES};

/// Table entries 0 and 1 are reserved: the first data cluster is number 2.
pub const FAT_START_ENT: u32 = 2;

/// Largest data-cluster count each width may address. These are the values
/// that decide the width, and they are NOT `2^12 - 1` and `2^16 - 1` — the top
/// entries of each table are reserved for end-of-chain and bad-cluster marks,
/// and the boundary sits below them.
pub const MAX_FAT12: u32 = 0x0000_0FF4;
pub const MAX_FAT16: u32 = 0x0000_FFF4;
pub const MAX_FAT32: u32 = 0x0FFF_FFF6;

/// How wide one table entry is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FatWidth { Fat12, Fat16, Fat32 }

impl FatWidth {
    /// Bits per table entry. # C: O(1)
    pub fn bits(self) -> u32 {
        match self { FatWidth::Fat12 => 12, FatWidth::Fat16 => 16, FatWidth::Fat32 => 32 }
    }

    /// Largest data-cluster count this width addresses. # C: O(1)
    pub fn max_clusters(self) -> u32 {
        match self { FatWidth::Fat12 => MAX_FAT12, FatWidth::Fat16 => MAX_FAT16, FatWidth::Fat32 => MAX_FAT32 }
    }
}

/// Why a volume's geometry is unusable.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum GeometryError {
    /// The root directory's entry count is not a whole number of sectors.
    BadRootEntries,
    /// The data area starts past the end of the volume.
    DataBeyondVolume,
    /// More data clusters than the table width can address.
    TooManyClusters,
}

impl GeometryError {
    /// # C: O(1)
    pub fn errno(self) -> Errno { Errno::Einval }
}

/// Where each region of the volume begins, in sectors, and how it is counted.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Geometry {
    pub width: FatWidth,
    pub sector_size: u32,
    pub sec_per_clus: u32,
    /// First sector of the first table.
    pub fat_start: u32,
    /// Table length in sectors.
    pub fat_length: u32,
    /// First sector of the fixed root directory. FAT32 has none; the value is
    /// still where the data area would otherwise begin.
    pub dir_start: u32,
    /// Root-directory entries. Zero on FAT32.
    pub dir_entries: u32,
    /// First sector of the data area — the sector cluster 2 begins at.
    pub data_start: u32,
    /// Data clusters, after clamping to what the table can actually index.
    pub total_clusters: u32,
    /// One past the last valid cluster number.
    pub max_cluster: u32,
    /// Root cluster, FAT32 only.
    pub root_cluster: u32,
}

/// Table entries one table of `fat_length` sectors can hold.
///
/// Divided in the order that avoids overflowing on a large volume: for the
/// two widths that divide the sector evenly, entries-per-sector first.
/// # C: O(1)
pub fn fat_entries(width: FatWidth, sector_size: u32, fat_length: u32) -> u64 {
    if width == FatWidth::Fat12 {
        return u64::from(fat_length) * u64::from(sector_size) * 8 / u64::from(width.bits());
    }
    let per_sector = u64::from(sector_size) * 8 / u64::from(width.bits());
    per_sector * u64::from(fat_length)
}

/// Resolve a validated boot sector into a volume layout.
///
/// The order is load-bearing and mirrors the reference exactly. The data area
/// is placed first, because the cluster count is derived from where it starts;
/// the width is decided from that count BEFORE the count is clamped, because
/// the clamp needs the width to know how many entries a table holds; and the
/// clamp comes before the range check, so a volume whose table is shorter than
/// its data area mounts with the clusters the table can reach instead of being
/// refused.
/// # C: O(1)
pub fn resolve(bpb: &Bpb) -> Result<Geometry, GeometryError> {
    let dir_per_sector = bpb.dir_per_sector();
    if dir_per_sector == 0 || bpb.dir_entries % dir_per_sector != 0 {
        return Err(GeometryError::BadRootEntries);
    }
    let fat_start = bpb.reserved;
    let fat_length = bpb.fat_length();
    let dir_start = fat_start + bpb.fats * fat_length;
    let rootdir_sectors = bpb.dir_entries * DIR_ENTRY_BYTES / bpb.sector_size;
    let data_start = dir_start + rootdir_sectors;
    let total_sectors = bpb.total_sectors();
    if total_sectors < data_start { return Err(GeometryError::DataBeyondVolume); }

    let mut total_clusters = (total_sectors - data_start) / bpb.sec_per_clus;
    // The width is derived, not declared — except on FAT32, where the 32-bit
    // table-length field carrying the value IS the declaration.
    let width = if bpb.declares_fat32() {
        FatWidth::Fat32
    } else if total_clusters > MAX_FAT12 {
        FatWidth::Fat16
    } else {
        FatWidth::Fat12
    };

    // A table shorter than the data area caps the volume: clusters the table
    // cannot index are not addressable, whatever the sector count implies.
    let table_entries = fat_entries(width, bpb.sector_size, fat_length);
    let indexable = table_entries.saturating_sub(u64::from(FAT_START_ENT));
    total_clusters = core::cmp::min(u64::from(total_clusters), indexable) as u32;
    if total_clusters > width.max_clusters() { return Err(GeometryError::TooManyClusters); }

    Ok(Geometry {
        width,
        sector_size: bpb.sector_size,
        sec_per_clus: bpb.sec_per_clus,
        fat_start,
        fat_length,
        dir_start,
        dir_entries: bpb.dir_entries,
        data_start,
        total_clusters,
        max_cluster: total_clusters + FAT_START_ENT,
        root_cluster: bpb.root_cluster,
    })
}

impl Geometry {
    /// First sector of data cluster `cluster`, or `None` when the cluster is
    /// not one this volume has. Cluster numbers below the first data cluster
    /// name reserved table entries and address no data at all.
    /// # C: O(1)
    pub fn cluster_sector(&self, cluster: u32) -> Option<u32> {
        if cluster < FAT_START_ENT || cluster >= self.max_cluster { return None; }
        let index = cluster - FAT_START_ENT;
        index.checked_mul(self.sec_per_clus)?.checked_add(self.data_start)
    }

    /// Bytes per cluster. # C: O(1)
    pub fn cluster_bytes(&self) -> u64 { u64::from(self.sector_size) * u64::from(self.sec_per_clus) }

    /// Whether this volume keeps its root directory in a fixed region rather
    /// than in an ordinary cluster chain. # C: O(1)
    pub fn has_fixed_root(&self) -> bool { self.width != FatWidth::Fat32 }
}

#[cfg(test)]
#[path = "geometry/tests.rs"]
mod tests;
