//! The stream extension entry: where a file's data is, and how much of it is
//! real.
//!
//! Two lengths, not one. `size` is what the allocation covers; `valid_size` is
//! how much of it has been written. Reading past the valid size returns zeros
//! rather than whatever the clusters last held, which is how exFAT gives a
//! file a tail without leaking the previous owner's bytes — and reporting
//! `size` as the file's length while reading past `valid_size` does exactly
//! that leak.

use crate::chain::Chain;
use crate::uapi::*;

/// The second entry of a set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StreamEntry {
    pub flags: u8,
    /// Name length in UTF-16 units.
    pub name_len: u8,
    pub name_hash: u16,
    /// Bytes actually written.
    pub valid_size: u64,
    pub start_cluster: u32,
    /// Bytes the allocation covers.
    pub size: u64,
}

impl StreamEntry {
    /// Whether the run is recorded without table entries. # C: O(1)
    pub fn contiguous(&self) -> bool { self.flags & ALLOC_NO_FAT_CHAIN == ALLOC_NO_FAT_CHAIN }

    /// Whether this entry can hold clusters at all. # C: O(1)
    pub fn allocated(&self) -> bool {
        self.flags & ALLOC_POSSIBLE != 0 && self.start_cluster != 0 && self.size != 0
    }

    /// The run this entry names, on a volume with `cluster_bytes` per cluster.
    /// # C: O(1)
    pub fn chain(&self, cluster_bytes: u64) -> Chain {
        if self.start_cluster == 0 || self.size == 0 {
            return Chain { dir: EOF_CLUSTER, size: 0, flags: self.flags };
        }
        let clusters = u32::try_from(self.size.div_ceil(cluster_bytes)).unwrap_or(u32::MAX);
        Chain { dir: self.start_cluster, size: clusters, flags: self.flags }
    }
}

/// Read one 16-bit field. # C: O(1)
fn le16(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }

/// Read one 32-bit field. # C: O(1)
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Read one 64-bit field. # C: O(1)
fn le64(bytes: &[u8], at: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(out)
}

/// Decode a stream extension entry. # C: O(1)
pub fn parse(bytes: &[u8]) -> Option<StreamEntry> {
    if bytes.len() < DENTRY_BYTES || bytes[0] != TYPE_STREAM { return None; }
    Some(StreamEntry {
        flags: bytes[STREAM_OFF_FLAGS],
        name_len: bytes[STREAM_OFF_NAME_LEN],
        name_hash: le16(bytes, STREAM_OFF_NAME_HASH),
        valid_size: le64(bytes, STREAM_OFF_VALID_SIZE),
        start_cluster: le32(bytes, STREAM_OFF_START_CLU),
        size: le64(bytes, STREAM_OFF_SIZE),
    })
}

/// Lay a stream extension entry out. # C: O(1)
pub fn write(entry: &StreamEntry, out: &mut [u8]) {
    out[..DENTRY_BYTES].fill(0);
    out[0] = TYPE_STREAM;
    out[STREAM_OFF_FLAGS] = entry.flags;
    out[STREAM_OFF_NAME_LEN] = entry.name_len;
    out[STREAM_OFF_NAME_HASH..STREAM_OFF_NAME_HASH + 2]
        .copy_from_slice(&entry.name_hash.to_le_bytes());
    out[STREAM_OFF_VALID_SIZE..STREAM_OFF_VALID_SIZE + 8]
        .copy_from_slice(&entry.valid_size.to_le_bytes());
    out[STREAM_OFF_START_CLU..STREAM_OFF_START_CLU + 4]
        .copy_from_slice(&entry.start_cluster.to_le_bytes());
    out[STREAM_OFF_SIZE..STREAM_OFF_SIZE + 8].copy_from_slice(&entry.size.to_le_bytes());
}

/// Decode one name entry's characters. # C: O(1)
pub fn parse_name(bytes: &[u8]) -> Option<[u16; NAME_CHARS_PER_ENTRY]> {
    if bytes.len() < DENTRY_BYTES || bytes[0] != TYPE_NAME { return None; }
    let mut out = [0u16; NAME_CHARS_PER_ENTRY];
    for (i, unit) in out.iter_mut().enumerate() {
        let at = NAME_OFF_CHARS + i * 2;
        *unit = le16(bytes, at);
    }
    Some(out)
}

/// Lay one name entry out, padding the units it does not need with zero.
/// # C: O(NAME_CHARS_PER_ENTRY)
pub fn write_name(units: &[u16], out: &mut [u8]) {
    out[..DENTRY_BYTES].fill(0);
    out[0] = TYPE_NAME;
    out[NAME_OFF_FLAGS] = 0;
    for (i, unit) in units.iter().take(NAME_CHARS_PER_ENTRY).enumerate() {
        let at = NAME_OFF_CHARS + i * 2;
        out[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
}

/// The allocation flags a run of `size` bytes deserves.
///
/// A run of nothing is recorded as chained, not contiguous: there is no run to
/// be contiguous, and an empty file marked contiguous claims cluster zero.
/// # C: O(1)
pub fn flags_for_new(size: u64) -> u8 {
    if size == 0 { ALLOC_FAT_CHAIN } else { ALLOC_NO_FAT_CHAIN }
}
