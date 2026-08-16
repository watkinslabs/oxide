//! A run of clusters, and the two ways exFAT records one.
//!
//! This is the difference between exFAT and FAT that touches everything else.
//! A FAT file is always a linked list through the table. An exFAT file may
//! instead be a CONTIGUOUS run recorded only as a first cluster and a length,
//! with the table holding nothing for it at all — that is what `NoFatChain`
//! means. Reading such a file through the table reads whatever the table's
//! stale bytes happen to say.
//!
//! A run stays contiguous only while it can. The moment an allocation cannot
//! extend it in place, the run is written out as a real chain first and the
//! flag flips; nothing may append to a contiguous run and leave the flag set.

use syscall::errno::Errno;

use crate::geometry::Geometry;
use crate::uapi::{ALLOC_FAT_CHAIN, ALLOC_NO_FAT_CHAIN, EOF_CLUSTER};

/// A file's or directory's clusters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Chain {
    /// First cluster, or `EOF_CLUSTER` when nothing is allocated.
    pub dir: u32,
    /// Clusters in the run.
    pub size: u32,
    /// `ALLOC_FAT_CHAIN` or `ALLOC_NO_FAT_CHAIN`.
    pub flags: u8,
}

impl Chain {
    /// # C: O(1)
    pub fn new(dir: u32, size: u32, flags: u8) -> Self { Self { dir, size, flags } }

    /// A chain with nothing allocated, which a first write will fill.
    /// # C: O(1)
    pub fn empty() -> Self { Self { dir: EOF_CLUSTER, size: 0, flags: ALLOC_NO_FAT_CHAIN } }

    /// Whether this run is recorded without table entries. # C: O(1)
    pub fn contiguous(&self) -> bool { self.flags == ALLOC_NO_FAT_CHAIN }

    /// Whether anything is allocated at all. # C: O(1)
    pub fn is_empty(&self) -> bool { self.size == 0 || self.dir == EOF_CLUSTER || self.dir == 0 }
}

/// Where a table lives, and how it is read.
pub trait FatAccess {
    /// The entry for `cluster`.
    fn get(&self, cluster: u32) -> Result<u32, Errno>;
}

/// The cluster holding index `index` of a run.
///
/// A contiguous run answers by arithmetic and never touches the table, which
/// is the whole point of the flag; a chained one walks. Walking past the
/// declared size is an error rather than a longer file: the size is what the
/// entry set promised, and following further reads clusters the file does not
/// own.
/// # C: O(1) contiguous, O(index) chained
pub fn cluster_at(geo: &Geometry, fat: &impl FatAccess, chain: &Chain, index: u32)
    -> Result<u32, Errno> {
    if chain.is_empty() { return Err(Errno::Eio); }
    if index >= chain.size { return Err(Errno::Eio); }
    if chain.contiguous() {
        let cluster = chain.dir.checked_add(index).ok_or(Errno::Eio)?;
        if !geo.valid_cluster(cluster) { return Err(Errno::Eio); }
        return Ok(cluster);
    }
    let mut cluster = chain.dir;
    for _ in 0..index {
        if !geo.valid_cluster(cluster) { return Err(Errno::Eio); }
        let next = fat.get(cluster)?;
        if next == EOF_CLUSTER { return Err(Errno::Eio); }
        if !geo.valid_cluster(next) { return Err(Errno::Eio); }
        cluster = next;
    }
    Ok(cluster)
}

/// Every cluster of a run, in order.
///
/// A chain longer than the volume has clusters is a loop, and is reported as
/// one rather than walked forever.
/// # C: O(chain length)
pub fn walk(geo: &Geometry, fat: &impl FatAccess, chain: &Chain)
    -> Result<alloc::vec::Vec<u32>, Errno> {
    let mut out = alloc::vec::Vec::new();
    if chain.is_empty() { return Ok(out); }
    if chain.contiguous() {
        for i in 0..chain.size {
            let cluster = chain.dir.checked_add(i).ok_or(Errno::Eio)?;
            if !geo.valid_cluster(cluster) { return Err(Errno::Eio); }
            out.push(cluster);
        }
        return Ok(out);
    }
    let mut cluster = chain.dir;
    while out.len() < chain.size as usize {
        if !geo.valid_cluster(cluster) { return Err(Errno::Eio); }
        out.push(cluster);
        let next = fat.get(cluster)?;
        if next == EOF_CLUSTER { break; }
        cluster = next;
    }
    if out.len() != chain.size as usize { return Err(Errno::Eio); }
    Ok(out)
}

/// The last cluster of a run. # C: O(1) contiguous, O(size) chained
pub fn last_cluster(geo: &Geometry, fat: &impl FatAccess, chain: &Chain) -> Result<u32, Errno> {
    if chain.is_empty() { return Err(Errno::Eio); }
    cluster_at(geo, fat, chain, chain.size - 1)
}

/// How long a chained run actually is, by following it.
///
/// Used where the stored size cannot be trusted — a directory's, which no
/// entry records. A run longer than the volume's cluster count is a loop.
/// # C: O(chain length)
pub fn count(geo: &Geometry, fat: &impl FatAccess, first: u32) -> Result<u32, Errno> {
    if first == 0 || first == EOF_CLUSTER { return Ok(0); }
    let mut cluster = first;
    let mut seen = 0u32;
    loop {
        if !geo.valid_cluster(cluster) { return Err(Errno::Eio); }
        seen += 1;
        if seen > geo.num_clusters { return Err(Errno::Eio); }
        let next = fat.get(cluster)?;
        if next == EOF_CLUSTER { return Ok(seen); }
        cluster = next;
    }
}

/// The flags byte a run of `size` clusters starting at `first` deserves, given
/// whether it is laid out end to end. # C: O(1)
pub fn flags_for(contiguous: bool) -> u8 {
    if contiguous { ALLOC_NO_FAT_CHAIN } else { ALLOC_FAT_CHAIN }
}

#[cfg(test)]
#[path = "tests/chain.rs"]
mod tests;
