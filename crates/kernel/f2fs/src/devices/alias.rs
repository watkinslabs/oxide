//! A file that stands for a whole member device.
//!
//! An aliasing inode owns exactly one member's blocks and nothing else: its
//! cached read extent is that member's entire span, and the point of the file
//! is to hold those blocks out of the allocator so something outside the
//! filesystem can use the member directly. Deleting the file hands the span
//! back.
//!
//! Every rule here exists because the alternative silently hands the same
//! blocks to two owners:
//!
//! - The flag means nothing unless the volume carries the feature, and a
//!   volume that does not carry it has an ordinary file with a high flag bit.
//! - An unpinned alias would be moved by the cleaner, and the member's blocks
//!   would then be somewhere else while the file still claims the span.
//! - An extent matching NO member describes blocks that are not a device.
//! - Member zero is where the metadata lives; aliasing it hands away the
//!   superblock.
//! - A zoned member cannot be handed to a writer that does not honour zones.

use crate::flags::{FEATURE_DEVICE_ALIAS, F2FS_DEVICE_ALIAS_FL};
use crate::node::Inode;

use super::table::DevTable;

/// Why an aliasing inode is not usable as one.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AliasError {
    /// The flag is set on a volume that does not carry the feature.
    FeatureOff,
    /// The file is not pinned, so the cleaner could move it.
    NotPinned,
    /// The extent is not a member's whole span.
    NoSuchDevice,
    /// The extent is member zero's span, which holds the metadata.
    MetaDevice,
    /// The member is zoned, and its writes are not the filesystem's to place.
    Zoned,
}

/// Whether `flags` marks an aliasing inode. # C: O(1)
pub fn is_alias(flags: u32) -> bool { flags & F2FS_DEVICE_ALIAS_FL != 0 }

/// Whether an aliasing inode may be used, and which member it stands for.
///
/// `zoned` answers whether a member index is a zoned device; a volume with no
/// zoned members answers false for every index.
/// # C: O(devices)
pub fn resolve(
    i: &Inode,
    feature: u32,
    pinned: bool,
    table: &DevTable,
    zoned: impl Fn(usize) -> bool,
) -> Result<usize, AliasError> {
    if feature & FEATURE_DEVICE_ALIAS == 0 { return Err(AliasError::FeatureOff); }
    if !pinned { return Err(AliasError::NotPinned); }
    let (_, blk, len) = i.cached_extent().ok_or(AliasError::NoSuchDevice)?;
    let end = blk.checked_add(len - 1).ok_or(AliasError::NoSuchDevice)?;
    for (idx, d) in table.devs().iter().enumerate() {
        if d.start_blk != blk || d.end_blk != end { continue; }
        if idx == 0 { return Err(AliasError::MetaDevice); }
        if zoned(idx) { return Err(AliasError::Zoned); }
        return Ok(idx);
    }
    Err(AliasError::NoSuchDevice)
}

/// Whether an inode's flag word is consistent with the volume and its pinning,
/// checked at the point every inode is read.
///
/// A non-aliasing inode passes unconditionally; the two conditions are only
/// meaningful once the flag is set.
/// # C: O(1)
pub fn flag_ok(flags: u32, feature: u32, pinned: bool) -> bool {
    if !is_alias(flags) { return true; }
    feature & FEATURE_DEVICE_ALIAS != 0 && pinned
}
