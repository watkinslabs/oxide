//! The attribute word, and the mode a record presents as.
//!
//! NTFS records a security descriptor per file, which is an access-control
//! list rather than a mode. What a caller sees is the MOUNT's answer —
//! `uid=`, `gid=`, `fmask=`, `dmask=` — with one bit of the medium consulted:
//! read-only, which removes the write bits.

use crate::opts::Options;
use crate::uapi::{FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
                  FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM};

/// The write bits, which the read-only attribute removes.
const WRITE_BITS: u16 = 0o222;
/// Every permission bit a mask can leave in place.
const PERM_BITS: u16 = 0o777;

/// The mode a record presents with. # C: O(1)
pub fn make_mode(attributes: u32, opts: &Options) -> u16 {
    let is_dir = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let base = if is_dir { PERM_BITS & !opts.dmask } else { PERM_BITS & !opts.fmask };
    if attributes & FILE_ATTRIBUTE_READONLY != 0 { base & !WRITE_BITS } else { base }
}

/// The attribute word a mode change produces.
///
/// Only the read-only bit can be reached this way: it is the only permission
/// the medium records that a POSIX mode maps onto.
/// # C: O(1)
pub fn attrs_for_mode(attributes: u32, mode: u16) -> u32 {
    if mode & WRITE_BITS == 0 { attributes | FILE_ATTRIBUTE_READONLY }
    else { attributes & !FILE_ATTRIBUTE_READONLY }
}

/// Whether a record should be hidden from a listing, given the mount.
///
/// The volume's own metadata files carry both the hidden and system bits, and
/// a listing that shows them puts `$MFT` and `$Bitmap` in the root of every
/// mount.
/// # C: O(1)
pub fn hidden_from(attributes: u32, opts: &Options) -> bool {
    if opts.show_sys_files { return false; }
    attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0
}

/// Whether a record is a reparse point. # C: O(1)
pub fn is_reparse(attributes: u32) -> bool { attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 }

/// The attribute word after a write, which marks the file changed. # C: O(1)
pub fn mark_archived(attributes: u32) -> u32 { attributes | FILE_ATTRIBUTE_ARCHIVE }
