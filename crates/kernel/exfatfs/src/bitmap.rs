//! The allocation bitmap: one bit per data cluster, and the only truth about
//! which clusters are free.
//!
//! This is the second half of the difference from FAT. FAT decides a cluster
//! is free by reading a zero out of the table; exFAT reads the BITMAP, because
//! a contiguous run has no table entries and every one of its clusters would
//! read as free. Allocating from the table on this filesystem hands out
//! clusters that are already in use.
//!
//! Bit zero is cluster 2: the two reserved clusters have no bits, so every
//! index here is a cluster number less two.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::uapi::{FIRST_CLUSTER, RESERVED_CLUSTERS};

/// Bits in one byte, as the layout counts them.
const BITS_PER_BYTE: u32 = 8;

/// The bitmap, held whole in memory.
pub struct Bitmap {
    bytes: Vec<u8>,
    /// Data clusters the volume has, which is how many bits are meaningful.
    /// Bits past this are padding and must never be handed out.
    clusters: u32,
}

impl Bitmap {
    /// # C: O(1)
    pub fn new(bytes: Vec<u8>, clusters: u32) -> Self { Self { bytes, clusters } }

    /// The bitmap's bytes, to write a sector back. # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes }

    /// Data clusters the bitmap covers. # C: O(1)
    pub fn clusters(&self) -> u32 { self.clusters }

    /// Bit index of a cluster, or `None` when it is not a data cluster.
    /// # C: O(1)
    fn index_of(&self, cluster: u32) -> Option<u32> {
        if cluster < FIRST_CLUSTER { return None; }
        let index = cluster - RESERVED_CLUSTERS;
        if index >= self.clusters { return None; }
        Some(index)
    }

    /// Byte and bit within it. # C: O(1)
    fn position(&self, index: u32) -> Option<(usize, u8)> {
        let byte = (index / BITS_PER_BYTE) as usize;
        if byte >= self.bytes.len() { return None; }
        Some((byte, (index % BITS_PER_BYTE) as u8))
    }

    /// Whether `cluster` is allocated. A cluster the bitmap does not cover
    /// reads as allocated, so nothing hands it out. # C: O(1)
    pub fn is_set(&self, cluster: u32) -> bool {
        let Some(index) = self.index_of(cluster) else { return true };
        let Some((byte, bit)) = self.position(index) else { return true };
        self.bytes[byte] & (1 << bit) != 0
    }

    /// Claim `cluster`. # C: O(1)
    pub fn set(&mut self, cluster: u32) -> Result<(), Errno> {
        let index = self.index_of(cluster).ok_or(Errno::Eio)?;
        let (byte, bit) = self.position(index).ok_or(Errno::Eio)?;
        self.bytes[byte] |= 1 << bit;
        Ok(())
    }

    /// Release `cluster`. # C: O(1)
    pub fn clear(&mut self, cluster: u32) -> Result<(), Errno> {
        let index = self.index_of(cluster).ok_or(Errno::Eio)?;
        let (byte, bit) = self.position(index).ok_or(Errno::Eio)?;
        self.bytes[byte] &= !(1 << bit);
        Ok(())
    }

    /// The first free cluster at or after `from`, wrapping once to the start
    /// of the heap.
    ///
    /// Wrapping is what makes a volume whose free space sits before the search
    /// hint usable at all: without it, a delete near the front is never
    /// reused until a remount resets the hint.
    /// # C: O(clusters)
    pub fn find_free(&self, from: u32) -> Option<u32> {
        let start = if self.index_of(from).is_some() { from } else { FIRST_CLUSTER };
        let end = FIRST_CLUSTER + self.clusters;
        for cluster in start..end {
            if !self.is_set(cluster) { return Some(cluster); }
        }
        for cluster in FIRST_CLUSTER..start {
            if !self.is_set(cluster) { return Some(cluster); }
        }
        None
    }

    /// How many clusters are allocated. # C: O(bitmap bytes)
    pub fn used(&self) -> u32 {
        let mut used = 0u32;
        for cluster in FIRST_CLUSTER..FIRST_CLUSTER + self.clusters {
            if self.is_set(cluster) { used += 1; }
        }
        used
    }

    /// Whether a whole run is allocated, which a truncation checks before
    /// releasing it. # C: O(count)
    pub fn range_set(&self, cluster: u32, count: u32) -> bool {
        (0..count).all(|i| cluster.checked_add(i).is_some_and(|c| self.is_set(c)))
    }

    /// Index of the bitmap sector holding `cluster`'s bit, counted from the
    /// start of the bitmap. # C: O(1)
    pub fn sector_index(&self, cluster: u32, sector_bits: u8) -> Option<u64> {
        let index = self.index_of(cluster)?;
        Some(u64::from(index / BITS_PER_BYTE) >> sector_bits)
    }

    /// The bytes of one bitmap sector, to write it back. # C: O(sector bytes)
    pub fn sector_bytes(&self, sector: u64, sector_size: u32) -> Option<&[u8]> {
        let start = usize::try_from(sector * u64::from(sector_size)).ok()?;
        let end = start.checked_add(sector_size as usize)?;
        // The last sector of the bitmap may be shorter than a sector only on a
        // malformed volume: the entry's size is a whole number of clusters.
        self.bytes.get(start..end)
    }
}

/// Bytes a bitmap covering `clusters` data clusters occupies. # C: O(1)
pub fn bytes_for(clusters: u32) -> u64 { u64::from(clusters).div_ceil(u64::from(BITS_PER_BYTE)) }

#[cfg(test)]
#[path = "tests/bitmap.rs"]
mod tests;
