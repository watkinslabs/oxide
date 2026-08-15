//! The allocation table, and walking a file's clusters through it.
//!
//! Two things here are easy to get subtly wrong and hard to notice.
//!
//! A FAT12 entry is twelve bits, so entries share bytes and alternate between
//! the low and high nibble of the byte they share. An entry also straddles the
//! boundary between two table sectors, which is why the whole table is
//! addressed as bytes here rather than a sector at a time.
//!
//! And a value at or above the bad-cluster mark ENDS a chain rather than
//! failing it — the reference folds bad and every reserved value above it into
//! end-of-chain. A walker that instead errors turns a volume with one marked
//! cluster into a volume that cannot be read.

use alloc::vec::Vec;

use crate::geometry::{FatWidth, Geometry, FAT_START_ENT};

/// First value that is not a usable next-cluster number, per width. Bad
/// clusters and every reserved value above them live here.
pub const BAD_FAT12: u32 = 0x0000_0FF7;
pub const BAD_FAT16: u32 = 0x0000_FFF7;
pub const BAD_FAT32: u32 = 0x0FFF_FFF7;

/// A table entry, once read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Link {
    /// Belongs to no file.
    Free,
    /// The chain continues at this cluster.
    Next(u32),
    /// The chain ends here. A bad-cluster mark reads as this, exactly as the
    /// reference folds it.
    End,
}

impl FatWidth {
    /// First value that is not a usable next-cluster number. # C: O(1)
    pub fn bad_mark(self) -> u32 {
        match self { FatWidth::Fat12 => BAD_FAT12, FatWidth::Fat16 => BAD_FAT16, FatWidth::Fat32 => BAD_FAT32 }
    }

    /// Mask covering the bits an entry actually carries. FAT32 entries are 28
    /// bits: the top four are reserved and MUST be ignored when reading, or
    /// every entry on a volume some other system wrote reads as out of range.
    /// # C: O(1)
    pub fn entry_mask(self) -> u32 {
        match self { FatWidth::Fat12 => 0x0000_0FFF, FatWidth::Fat16 => 0x0000_FFFF, FatWidth::Fat32 => 0x0FFF_FFFF }
    }
}

/// Byte offset of `cluster`'s entry within the table.
///
/// FAT12 packs two entries into three bytes, so the offset advances by one and
/// a half bytes per entry — which is where the shared byte comes from.
/// # C: O(1)
pub fn entry_offset(width: FatWidth, cluster: u32) -> u64 {
    let n = u64::from(cluster);
    match width {
        FatWidth::Fat12 => n + n / 2,
        FatWidth::Fat16 => n * 2,
        FatWidth::Fat32 => n * 4,
    }
}

/// Read `cluster`'s entry from a byte view of the table.
///
/// `None` when the entry lies outside the bytes provided — a truncated or
/// short table must not read whatever follows it in memory.
/// # C: O(1)
pub fn read_entry(width: FatWidth, table: &[u8], cluster: u32) -> Option<Link> {
    let at = entry_offset(width, cluster);
    let raw = match width {
        FatWidth::Fat12 => {
            let a = *table.get(usize::try_from(at).ok()?)?;
            let b = *table.get(usize::try_from(at + 1).ok()?)?;
            let pair = u32::from(a) | (u32::from(b) << 8);
            // Even entries take the low twelve bits of the pair, odd entries
            // the high twelve. They share the middle byte.
            if cluster & 1 == 0 { pair & 0xFFF } else { pair >> 4 }
        }
        FatWidth::Fat16 => {
            let a = *table.get(usize::try_from(at).ok()?)?;
            let b = *table.get(usize::try_from(at + 1).ok()?)?;
            u32::from(u16::from_le_bytes([a, b]))
        }
        FatWidth::Fat32 => {
            let mut bytes = [0u8; 4];
            for (i, slot) in bytes.iter_mut().enumerate() {
                *slot = *table.get(usize::try_from(at + i as u64).ok()?)?;
            }
            u32::from_le_bytes(bytes)
        }
    } & width.entry_mask();
    Some(classify(width, raw))
}

/// What a raw entry value means. # C: O(1)
pub fn classify(width: FatWidth, raw: u32) -> Link {
    if raw == 0 { return Link::Free; }
    if raw >= width.bad_mark() { return Link::End; }
    if raw < FAT_START_ENT { return Link::End; }
    Link::Next(raw)
}

/// Why a chain walk stopped early.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ChainError {
    /// A link named a cluster this volume does not have.
    OutOfRange,
    /// The table is shorter than the entry the walk needed.
    TableTooShort,
    /// The chain revisited a cluster, or ran longer than the volume has
    /// clusters. Either way it does not terminate.
    Cycle,
}

/// Walk the chain starting at `first`, returning its clusters in order.
///
/// A free entry mid-chain, a link past the end of the volume, and a chain
/// longer than the volume are each refused rather than followed: a corrupt
/// table must not make a reader loop forever or read another file's data.
/// The length bound is the volume's own cluster count, which is the most a
/// chain can visit without repeating.
/// # C: O(chain length)
pub fn walk(geo: &Geometry, table: &[u8], first: u32) -> Result<Vec<u32>, ChainError> {
    let mut out = Vec::new();
    if first < FAT_START_ENT || first >= geo.max_cluster { return Err(ChainError::OutOfRange); }
    let mut cluster = first;
    loop {
        out.push(cluster);
        if out.len() as u64 > u64::from(geo.total_clusters) { return Err(ChainError::Cycle); }
        match read_entry(geo.width, table, cluster).ok_or(ChainError::TableTooShort)? {
            Link::End => return Ok(out),
            // A free entry in the middle of a chain is a corrupt table: the
            // file claims a cluster the volume believes nobody owns.
            Link::Free => return Err(ChainError::OutOfRange),
            Link::Next(next) => {
                if next < FAT_START_ENT || next >= geo.max_cluster { return Err(ChainError::OutOfRange); }
                cluster = next;
            }
        }
    }
}

/// Clusters a file of `size` bytes occupies on this volume. A zero-length
/// file occupies none, which is why its entry names no cluster at all.
/// # C: O(1)
pub fn clusters_for_size(geo: &Geometry, size: u64) -> u64 {
    let per = geo.cluster_bytes();
    if per == 0 { return 0; }
    size.div_ceil(per)
}

#[cfg(test)]
#[path = "chain/tests.rs"]
mod tests;
