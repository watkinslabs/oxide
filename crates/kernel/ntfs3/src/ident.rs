//! What an inode number is here.
//!
//! Unlike FAT and exFAT, this filesystem HAS one: the MFT record number is the
//! identity, stable for as long as the record is and unique because two files
//! cannot share a record. Nothing has to be derived.
//!
//! What does need care is the SEQUENCE beside it. A record number alone is
//! reused the moment the record is; a reference carrying the sequence the
//! record had names the file that was there rather than whichever file took
//! its place.

use crate::record::Reference;
use crate::uapi::{MFT_REC_USER, ROOT_INO};

/// The inode number for a record. # C: O(1)
pub fn inode_number(number: u64) -> u64 { number }

/// The root's number, which is a fixed record. # C: O(1)
pub fn root_inode_number() -> u64 { ROOT_INO }

/// Whether a reference still names the record it was made against.
///
/// A sequence of zero means the reference does not care, which is what the
/// format uses for a reference made before the record had one.
/// # C: O(1)
pub fn reference_is_current(reference: &Reference, sequence: u16) -> bool {
    reference.sequence == 0 || reference.sequence == sequence
}

/// Whether a record number is one a user file may occupy.
///
/// The first two dozen are the volume's own metadata; presenting them as files
/// puts `$MFT` and `$Bitmap` in the root of every mount.
/// # C: O(1)
pub fn is_user_record(number: u64) -> bool { number >= MFT_REC_USER }

#[cfg(test)]
#[path = "tests/ident.rs"]
mod tests;
