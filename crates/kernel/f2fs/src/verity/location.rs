//! Where a verity file's metadata is, and the size rule that keeps it out of
//! the file's contents.
//!
//! A verity file's stored size is the size of its DATA. Its hash tree and its
//! descriptor are written past that, starting at the next alignment boundary,
//! in blocks the file's own index addresses. Nothing in the inode says where
//! the data stops and the tree starts except the size itself — so a reader
//! that treats the file's allocated extent as its contents hands the caller
//! the hash tree as if it were file data, and every checksum over that file
//! is then computed over the wrong bytes.

use super::uapi::*;
use super::VerityError;

/// Where the metadata begins, given the file's data size. # C: O(1)
pub fn metadata_pos(size: u64) -> u64 {
    let rem = size % METADATA_ALIGN;
    if rem == 0 { size } else { size.saturating_add(METADATA_ALIGN - rem) }
}

/// The bytes of a verity file a read may return.
///
/// The clamp is against the data size, never against what the file's blocks
/// cover: the blocks cover the tree too.
/// # C: O(1)
pub fn readable(size: u64, off: u64, len: u64) -> u64 {
    if off >= size { return 0; }
    len.min(size - off)
}

/// Whether a byte range lies wholly inside the file's data. # C: O(1)
pub fn is_data(size: u64, off: u64, len: u64) -> bool {
    off.checked_add(len).map(|end| end <= size).unwrap_or(false)
}

/// The pointer stored in the verity attribute.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Location {
    pub version: u32,
    /// Bytes of descriptor, signature included.
    pub size: u32,
    /// Where the descriptor sits, past the tree.
    pub pos: u64,
}

fn le32(b: &[u8], at: usize) -> u32 {
    let mut v = [0u8; U32_LEN];
    v.copy_from_slice(&b[at..at + U32_LEN]);
    u32::from_le_bytes(v)
}

fn le64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; U64_LEN];
    v.copy_from_slice(&b[at..at + U64_LEN]);
    u64::from_le_bytes(v)
}

/// Read the attribute value.
///
/// A value of the wrong length is not truncation to recover from: the record
/// is fixed-width, so any other width is a format this build does not know.
/// # C: O(1)
pub fn parse(value: &[u8]) -> Result<Location, VerityError> {
    if value.len() != LOCATION_SIZE { return Err(VerityError::UnknownFormat); }
    let version = le32(value, LOC_VERSION);
    if version != LOCATION_VERSION { return Err(VerityError::UnknownFormat); }
    Ok(Location { version, size: le32(value, LOC_SIZE), pos: le64(value, LOC_POS) })
}

/// Write one back. # C: O(1)
pub fn encode(loc: &Location) -> [u8; LOCATION_SIZE] {
    let mut out = [0u8; LOCATION_SIZE];
    out[LOC_VERSION..LOC_VERSION + U32_LEN].copy_from_slice(&loc.version.to_le_bytes());
    out[LOC_SIZE..LOC_SIZE + U32_LEN].copy_from_slice(&loc.size.to_le_bytes());
    out[LOC_POS..LOC_POS + U64_LEN].copy_from_slice(&loc.pos.to_le_bytes());
    out
}

/// Whether a location can be followed on a file of this size.
///
/// The lower bound is what matters: a descriptor claiming to sit INSIDE the
/// data would make the verified bytes overlap the bytes being verified, which
/// is how a crafted image gets its own hashes accepted.
/// # C: O(1)
pub fn check(loc: &Location, size: u64, max_file_bytes: u64) -> Result<(), VerityError> {
    let end = loc.pos.checked_add(loc.size as u64).ok_or(VerityError::Corrupted)?;
    if end > max_file_bytes { return Err(VerityError::Corrupted); }
    if loc.pos < metadata_pos(size) { return Err(VerityError::Corrupted); }
    if loc.size as usize > MAX_DESCRIPTOR_SIZE { return Err(VerityError::DescriptorTooLarge); }
    if (loc.size as usize) < DESCRIPTOR_SIZE { return Err(VerityError::TruncatedDescriptor); }
    Ok(())
}

/// Where the hash tree sits, and how far it runs, given a descriptor's own
/// account of its size. # C: O(1)
pub fn tree_span(size: u64, tree_size: u64) -> (u64, u64) {
    (metadata_pos(size), tree_size)
}
