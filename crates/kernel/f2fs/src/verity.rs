//! The descriptor a verity-protected file carries.
//!
//! A verity file's contents are hashed into a Merkle tree, and the tree and
//! the descriptor naming its root live PAST the file's data — at the next
//! alignment boundary above the stored size, in blocks the file's own index
//! addresses. The size in the inode is the size of the DATA, not of what the
//! file occupies.
//!
//! That single fact is the whole trap. A reader that takes the inode's blocks
//! as its contents returns the hash tree as file data; a reader that clamps
//! to the stored size but lets the file be written invalidates every hash it
//! carries. So a verity inode reads short of its extent and refuses writes,
//! and neither is optional.
//!
//! The descriptor is not stored in the attribute region: the region is capped
//! far below one tree block, and an attribute is not protected the way the
//! data is. What the attribute holds is a POINTER — a version, a length and a
//! position — and following it is what this module is for.
//!
//! Module manifest:
//! - `uapi`:       the on-disk numbers, offsets and widths.
//! - `location`:   the attribute's pointer, and the size rule it lives under.
//! - `descriptor`: the descriptor, its checks, and the tree it describes.
//! - `access`:     what may be done to a verity inode.

use syscall::errno::Errno;

pub mod uapi;
pub mod location;
pub mod descriptor;
pub mod access;
pub mod merkle;

pub use descriptor::Descriptor;
pub use location::{metadata_pos, Location};

/// Why verity metadata could not be used.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VerityError {
    /// A version or record width outside the one layout that exists.
    UnknownFormat,
    /// The inode is marked verity but carries no location attribute.
    NoDescriptor,
    /// The record stops before the fixed part ends.
    TruncatedDescriptor,
    /// Wider than will be read.
    DescriptorTooLarge,
    /// The location points inside the data, past the file, or wraps.
    Corrupted,
    /// Reserved bytes are not zero, so the descriptor carries a field this
    /// build would ignore.
    ReservedSet,
    /// A salt longer than the field holding it.
    BadSalt,
    /// A signature longer than the record holding it.
    SignatureOverflow,
    /// A hash this build cannot reproduce.
    UnsupportedHash,
    /// A tree block size the format does not admit, or too small for the
    /// digest it must hold two of.
    BadBlockSize,
    /// A tree deeper than will be described.
    TooManyLevels,
    /// The descriptor was built over a file of a different length.
    SizeMismatch,
    /// The file may not be written or resized.
    ReadOnlyFile,
    /// Verity is already on.
    AlreadyEnabled,
}

impl VerityError {
    /// What a caller reports for this. # C: O(1)
    pub fn errno(self) -> Errno { access::errno(self) }
}

/// Everything a verity inode's metadata says, once both records are read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Verity {
    pub location: Location,
    pub descriptor: Descriptor,
    /// Where the hash tree starts, and how many bytes it runs.
    pub tree_at: u64,
    pub tree_bytes: u64,
}

/// Resolve an inode's verity metadata from the two records that carry it.
///
/// `attr` is the attribute value; `desc_bytes` is what was read at the
/// position the attribute named. Both are checked against the inode's own
/// size, because the size is what separates the data from the metadata and a
/// descriptor that disagrees with it describes another file.
/// # C: O(levels)
pub fn resolve(
    attr: &[u8],
    desc_bytes: &[u8],
    inode_size: u64,
    max_file_bytes: u64,
) -> Result<Verity, VerityError> {
    let loc = location::parse(attr)?;
    location::check(&loc, inode_size, max_file_bytes)?;
    let want = loc.size as usize;
    let bytes = desc_bytes.get(..want).ok_or(VerityError::TruncatedDescriptor)?;
    let d = descriptor::parse(bytes)?;
    descriptor::check(&d, inode_size)?;
    let tree_bytes = descriptor::tree_size(&d, inode_size)?;
    let tree_at = location::metadata_pos(inode_size);
    // The descriptor sits past the tree. A position inside the tree would put
    // the descriptor's own bytes among the hashes covering the data, so the
    // overlap is refused. The writer places it exactly at the tree's end, so
    // this refuses nothing that was written correctly; it is stricter than
    // the reference, which bounds the position below only by where the
    // metadata starts.
    if loc.pos < tree_at.saturating_add(tree_bytes) { return Err(VerityError::Corrupted); }
    Ok(Verity { location: loc, descriptor: d, tree_at, tree_bytes })
}

#[cfg(test)]
#[path = "tests/verity.rs"]
mod tests;
