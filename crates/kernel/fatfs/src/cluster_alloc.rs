//! Changing the allocation table: claiming free clusters, linking them into a
//! chain, and releasing one.
//!
//! Reading a table is forgiving — a wrong answer shows the wrong bytes.
//! WRITING one is not: a mistake here hands a cluster to two files, or drops
//! one nobody can reach again, and the volume is then wrong for every other
//! system that reads it. Three rules follow from that, and each has a test.
//!
//! A twelve-bit entry shares a byte with its neighbour, so writing one must
//! PRESERVE the other's nibble. A search starts from a hint and wraps, so a
//! volume with a full tail still allocates from its head. And an allocation
//! that cannot be satisfied commits nothing: the reference marks entries as it
//! goes and reports the shortfall afterwards, which leaks every cluster it had
//! already claimed, so this one decides first and commits second.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::chain::{self, Link};
use crate::geometry::{FatWidth, Geometry, FAT_START_ENT};

/// End-of-chain value written into the last entry of a chain, per width.
/// Any value at or above the bad mark reads as an end; this is the one the
/// reference writes.
pub fn end_mark(width: FatWidth) -> u32 {
    match width {
        FatWidth::Fat12 => 0x0000_0FFF,
        FatWidth::Fat16 => 0x0000_FFFF,
        FatWidth::Fat32 => 0x0FFF_FFFF,
    }
}

/// Write one table entry.
///
/// The twelve-bit case reads the byte pair it shares with its neighbour and
/// merges, because half of that pair belongs to another cluster. Overwriting
/// the pair outright destroys the neighbour's entry — which is a chain
/// truncated or re-pointed somewhere else, discovered later as lost data.
/// # C: O(1)
pub fn write_entry(width: FatWidth, table: &mut [u8], cluster: u32, value: u32) -> Result<(), Errno> {
    let at = usize::try_from(chain::entry_offset(width, cluster)).map_err(|_| Errno::Eio)?;
    let value = value & width.entry_mask();
    match width {
        FatWidth::Fat12 => {
            if at + 1 >= table.len() { return Err(Errno::Eio); }
            let pair = u16::from_le_bytes([table[at], table[at + 1]]);
            let merged = if cluster & 1 == 0 {
                (pair & 0xF000) | (value as u16 & 0x0FFF)
            } else {
                (pair & 0x000F) | ((value as u16 & 0x0FFF) << 4)
            };
            table[at..at + 2].copy_from_slice(&merged.to_le_bytes());
        }
        FatWidth::Fat16 => {
            if at + 1 >= table.len() { return Err(Errno::Eio); }
            table[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
        }
        FatWidth::Fat32 => {
            if at + 3 >= table.len() { return Err(Errno::Eio); }
            // The top four bits are reserved and belong to whatever wrote them
            // first; the reference preserves them across a write.
            let existing = u32::from_le_bytes([table[at], table[at + 1], table[at + 2], table[at + 3]]);
            let merged = (existing & 0xF000_0000) | value;
            table[at..at + 4].copy_from_slice(&merged.to_le_bytes());
        }
    }
    Ok(())
}

/// Find `count` free clusters, starting the search after `hint` and wrapping.
///
/// Decides only — nothing is written. `ENOSPC` when the volume does not hold
/// that many, and in that case NOTHING has been claimed, so a failed
/// allocation cannot leak.
/// # C: O(total clusters)
pub fn find_free(geo: &Geometry, table: &[u8], hint: u32, count: usize) -> Result<Vec<u32>, Errno> {
    let mut found = Vec::with_capacity(count);
    if count == 0 { return Ok(found); }
    let span = geo.max_cluster.saturating_sub(FAT_START_ENT);
    if span == 0 { return Err(Errno::Enospc); }
    let first = if hint < FAT_START_ENT || hint + 1 >= geo.max_cluster {
        FAT_START_ENT
    } else {
        hint + 1
    };
    let mut cluster = first;
    for _ in 0..span {
        if chain::read_entry(geo.width, table, cluster) == Some(Link::Free) {
            found.push(cluster);
            if found.len() == count { return Ok(found); }
        }
        cluster += 1;
        // The search wraps: a volume whose tail is full still allocates from
        // its head, which is what keeps a nearly-full volume usable.
        if cluster >= geo.max_cluster { cluster = FAT_START_ENT; }
    }
    Err(Errno::Enospc)
}

/// Link `clusters` into a chain, ending it, and attach it to `tail` when one
/// is given.
///
/// The order is what makes an interrupted write safe to read: each new entry
/// is terminated BEFORE the previous one points at it, so a reader that stops
/// between the two sees a chain that ends early rather than one running into
/// an entry that says nothing.
/// # C: O(clusters)
pub fn link_chain(geo: &Geometry, table: &mut [u8], clusters: &[u32], tail: Option<u32>)
    -> Result<(), Errno> {
    if clusters.is_empty() { return Ok(()); }
    for (i, cluster) in clusters.iter().enumerate() {
        let value = match clusters.get(i + 1) {
            Some(next) => *next,
            None => end_mark(geo.width),
        };
        write_entry(geo.width, table, *cluster, value)?;
    }
    if let Some(tail) = tail {
        write_entry(geo.width, table, tail, clusters[0])?;
    }
    Ok(())
}

/// Claim `count` clusters and link them, optionally onto an existing chain's
/// last cluster. Returns the clusters claimed, in order.
/// # C: O(total clusters)
pub fn allocate(geo: &Geometry, table: &mut [u8], hint: u32, count: usize, tail: Option<u32>)
    -> Result<Vec<u32>, Errno> {
    let clusters = find_free(geo, table, hint, count)?;
    link_chain(geo, table, &clusters, tail)?;
    Ok(clusters)
}

/// Release every cluster of the chain starting at `first`.
///
/// Walks with the reader, which already refuses a loop and a link past the
/// volume, so a corrupt chain cannot make this free clusters that belong to
/// something else.
/// # C: O(chain length)
pub fn free_chain(geo: &Geometry, table: &mut [u8], first: u32) -> Result<usize, Errno> {
    let clusters = chain::walk(geo, table, first).map_err(|_| Errno::Eio)?;
    for cluster in &clusters {
        write_entry(geo.width, table, *cluster, 0)?;
    }
    Ok(clusters.len())
}

/// Truncate a chain after `keep` clusters, releasing the rest. Returns the
/// clusters released. A `keep` of zero releases the whole chain.
/// # C: O(chain length)
pub fn truncate_chain(geo: &Geometry, table: &mut [u8], first: u32, keep: usize)
    -> Result<usize, Errno> {
    let clusters = chain::walk(geo, table, first).map_err(|_| Errno::Eio)?;
    if keep >= clusters.len() { return Ok(0); }
    // Terminate the survivor BEFORE freeing what followed, so a reader that
    // stops between the two never follows a link into a freed cluster.
    if keep > 0 { write_entry(geo.width, table, clusters[keep - 1], end_mark(geo.width))?; }
    for cluster in &clusters[keep..] {
        write_entry(geo.width, table, *cluster, 0)?;
    }
    Ok(clusters.len() - keep)
}

/// Free clusters on this volume. # C: O(total clusters)
pub fn count_free(geo: &Geometry, table: &[u8]) -> u32 {
    let mut free = 0;
    for cluster in FAT_START_ENT..geo.max_cluster {
        if chain::read_entry(geo.width, table, cluster) == Some(Link::Free) { free += 1; }
    }
    free
}

#[cfg(test)]
#[path = "cluster_alloc/tests.rs"]
mod tests;
