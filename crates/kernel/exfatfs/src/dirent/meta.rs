//! The entries that describe the VOLUME rather than a file.
//!
//! Three of them sit in the root directory and nowhere else: the allocation
//! bitmap, the up-case table and the volume label. A mount cannot allocate a
//! cluster or compare a name until it has found the first two, which is why
//! the root directory is read before anything else on the volume.

use alloc::string::String;

use crate::uapi::*;

/// Where the allocation bitmap lives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitmapEntry {
    /// Bit 0 selects the second bitmap, which only a `TexFAT` volume has.
    pub flags: u8,
    pub start_cluster: u32,
    pub size: u64,
}

/// Where the up-case table lives, and what it must sum to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UpcaseEntry {
    pub checksum: u32,
    pub start_cluster: u32,
    pub size: u64,
}

/// The volume's label.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VolumeLabel {
    pub units: alloc::vec::Vec<u16>,
}

impl VolumeLabel {
    /// # C: O(label length)
    pub fn as_string(&self) -> String { crate::name::decode(&self.units) }
}

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

/// Decode an allocation-bitmap entry. # C: O(1)
pub fn parse_bitmap(bytes: &[u8]) -> Option<BitmapEntry> {
    if bytes.len() < DENTRY_BYTES || bytes[0] != TYPE_BITMAP { return None; }
    Some(BitmapEntry {
        flags: bytes[BITMAP_OFF_FLAGS],
        start_cluster: le32(bytes, BITMAP_OFF_START_CLU),
        size: le64(bytes, BITMAP_OFF_SIZE),
    })
}

/// Decode an up-case table entry. # C: O(1)
pub fn parse_upcase(bytes: &[u8]) -> Option<UpcaseEntry> {
    if bytes.len() < DENTRY_BYTES || bytes[0] != TYPE_UPCASE { return None; }
    Some(UpcaseEntry {
        checksum: le32(bytes, UPCASE_OFF_CHECKSUM),
        start_cluster: le32(bytes, UPCASE_OFF_START_CLU),
        size: le64(bytes, UPCASE_OFF_SIZE),
    })
}

/// Decode a volume-label entry.
///
/// A label of zero characters is how a volume records having none, and reads
/// back as the empty string rather than as an absent entry.
/// # C: O(1)
pub fn parse_label(bytes: &[u8]) -> Option<VolumeLabel> {
    if bytes.len() < DENTRY_BYTES || bytes[0] != TYPE_VOLUME { return None; }
    let count = core::cmp::min(bytes[LABEL_OFF_CHAR_COUNT] as usize, VOLUME_LABEL_LEN);
    let mut units = alloc::vec::Vec::with_capacity(count);
    for i in 0..count {
        let at = LABEL_OFF_CHARS + i * 2;
        units.push(u16::from_le_bytes([bytes[at], bytes[at + 1]]));
    }
    Some(VolumeLabel { units })
}

/// Lay a volume-label entry out.
///
/// A label longer than the field holds is refused rather than truncated: a
/// silently shortened label is a different label.
/// # C: O(label length)
pub fn write_label(label: &[u16], out: &mut [u8]) -> Result<(), syscall::errno::Errno> {
    if label.len() > VOLUME_LABEL_LEN { return Err(syscall::errno::Errno::Einval); }
    out[..DENTRY_BYTES].fill(0);
    // A label of nothing is recorded by DELETING the entry, which is what an
    // implementation that removes a label does, so an empty label here still
    // writes a live entry with a zero count.
    out[0] = TYPE_VOLUME;
    out[LABEL_OFF_CHAR_COUNT] = label.len() as u8;
    for (i, unit) in label.iter().enumerate() {
        let at = LABEL_OFF_CHARS + i * 2;
        out[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

/// Lay an allocation-bitmap entry out. # C: O(1)
pub fn write_bitmap(entry: &BitmapEntry, out: &mut [u8]) {
    out[..DENTRY_BYTES].fill(0);
    out[0] = TYPE_BITMAP;
    out[BITMAP_OFF_FLAGS] = entry.flags;
    out[BITMAP_OFF_START_CLU..BITMAP_OFF_START_CLU + 4]
        .copy_from_slice(&entry.start_cluster.to_le_bytes());
    out[BITMAP_OFF_SIZE..BITMAP_OFF_SIZE + 8].copy_from_slice(&entry.size.to_le_bytes());
}

/// Lay an up-case table entry out. # C: O(1)
pub fn write_upcase(entry: &UpcaseEntry, out: &mut [u8]) {
    out[..DENTRY_BYTES].fill(0);
    out[0] = TYPE_UPCASE;
    out[UPCASE_OFF_CHECKSUM..UPCASE_OFF_CHECKSUM + 4]
        .copy_from_slice(&entry.checksum.to_le_bytes());
    out[UPCASE_OFF_START_CLU..UPCASE_OFF_START_CLU + 4]
        .copy_from_slice(&entry.start_cluster.to_le_bytes());
    out[UPCASE_OFF_SIZE..UPCASE_OFF_SIZE + 8].copy_from_slice(&entry.size.to_le_bytes());
}
