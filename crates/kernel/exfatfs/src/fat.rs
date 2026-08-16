//! The allocation table: four bytes per cluster, held whole in memory.
//!
//! The table is read at mount and every walk consults the copy, which is what
//! makes a chain walk cost no I/O. Writes go to the copy and to both on-disk
//! tables, so a volume with a mirror never has one table saying a file
//! continues and the other saying it ends.
//!
//! A table entry is only ever consulted for a CHAINED run. A contiguous one
//! carries no entries at all, so a value read for such a cluster is stale
//! bytes from whatever used the cluster before.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::chain::FatAccess;
use crate::geometry::Geometry;
use crate::uapi::{BAD_CLUSTER, EOF_CLUSTER, FAT_ENTRY_BYTES, FREE_CLUSTER};

/// The table, as read from the volume.
pub struct FatTable {
    bytes: Vec<u8>,
}

impl FatTable {
    /// # C: O(1)
    pub fn new(bytes: Vec<u8>) -> Self { Self { bytes } }

    /// The table's bytes, to write a sector of it back. # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes }

    /// Whether the table holds an entry for `cluster`. # C: O(1)
    pub fn covers(&self, cluster: u32) -> bool {
        (cluster as usize + 1) * FAT_ENTRY_BYTES <= self.bytes.len()
    }

    /// The raw entry for `cluster`, without interpretation. # C: O(1)
    pub fn raw(&self, cluster: u32) -> Result<u32, Errno> {
        if !self.covers(cluster) { return Err(Errno::Eio); }
        let at = cluster as usize * FAT_ENTRY_BYTES;
        Ok(u32::from_le_bytes([self.bytes[at], self.bytes[at + 1], self.bytes[at + 2],
                               self.bytes[at + 3]]))
    }

    /// Set the entry for `cluster` in the in-memory copy. # C: O(1)
    pub fn set(&mut self, cluster: u32, value: u32) -> Result<(), Errno> {
        if !self.covers(cluster) { return Err(Errno::Eio); }
        let at = cluster as usize * FAT_ENTRY_BYTES;
        self.bytes[at..at + FAT_ENTRY_BYTES].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    /// The sector of the table holding `cluster`'s entry, as bytes to write
    /// out. # C: O(sector bytes)
    pub fn sector_bytes(&self, geo: &Geometry, cluster: u32) -> Option<&[u8]> {
        let per = geo.sector_size as usize;
        let byte = cluster as usize * FAT_ENTRY_BYTES;
        let start = (byte / per) * per;
        self.bytes.get(start..start + per)
    }

    /// Index of the table sector holding `cluster`'s entry, counted from the
    /// start of the table. # C: O(1)
    pub fn sector_index(&self, geo: &Geometry, cluster: u32) -> u64 {
        (u64::from(cluster) * FAT_ENTRY_BYTES as u64) >> geo.sector_bits
    }
}

/// A table read with the volume's own rules applied.
pub struct Reader<'a> {
    pub table: &'a FatTable,
    pub geo: &'a Geometry,
}

impl FatAccess for Reader<'_> {
    fn get(&self, cluster: u32) -> Result<u32, Errno> {
        if !self.geo.valid_cluster(cluster) { return Err(Errno::Eio); }
        let raw = self.table.raw(cluster)?;
        // Anything above the bad-cluster marker is a reserved value; the
        // reference reads every one of them as the end of the chain rather
        // than following it somewhere arbitrary.
        let value = if raw > BAD_CLUSTER { EOF_CLUSTER } else { raw };
        // A chain that runs into a free or bad cluster is an inconsistent
        // volume, not a shorter file: the entry claims those clusters and the
        // table says nobody owns them.
        if value == FREE_CLUSTER || value == BAD_CLUSTER { return Err(Errno::Eio); }
        if value != EOF_CLUSTER && !self.geo.valid_cluster(value) { return Err(Errno::Eio); }
        Ok(value)
    }
}

/// Link `first`..`first + len - 1` into a chain, ending it.
///
/// This is what a contiguous run becomes when it can no longer stay
/// contiguous: the table entries it never had are written for the first time,
/// and only then may the flag flip.
/// # C: O(len)
pub fn write_contiguous_chain(table: &mut FatTable, first: u32, len: u32) -> Result<(), Errno> {
    if len == 0 { return Ok(()); }
    for i in 0..len - 1 {
        table.set(first + i, first + i + 1)?;
    }
    table.set(first + len - 1, EOF_CLUSTER)
}

#[cfg(test)]
#[path = "tests/fat.rs"]
mod tests;
