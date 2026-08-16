//! The attribute word, and the mode an entry presents as.
//!
//! exFAT stores no permission bits and no owner. What a file appears to be
//! owned by and permitted for is entirely the MOUNT's answer — `uid=`, `gid=`,
//! `fmask=`, `dmask=` — with one bit of the medium consulted: read-only, which
//! removes the write bits wherever they would otherwise be.

use crate::opts::Options;
use crate::uapi::{ATTR_ARCHIVE, ATTR_HIDDEN, ATTR_READONLY, ATTR_SUBDIR, ATTR_SYSTEM};

/// The write bits, which the read-only attribute removes.
const WRITE_BITS: u16 = 0o222;
/// Every permission bit a mask can leave in place.
const PERM_BITS: u16 = 0o777;

/// The mode an entry presents with. # C: O(1)
pub fn make_mode(attr: u16, opts: &Options) -> u16 {
    let is_dir = attr & ATTR_SUBDIR != 0;
    let base = if is_dir { PERM_BITS & !opts.dmask } else { PERM_BITS & !opts.fmask };
    if attr & ATTR_READONLY != 0 { base & !WRITE_BITS } else { base }
}

/// The attribute word a mode change produces.
///
/// Only the read-only bit can be reached this way, because it is the only
/// permission the medium records. A mode with no write bit anywhere sets it;
/// any write bit clears it.
/// # C: O(1)
pub fn attrs_for_mode(attr: u16, mode: u16) -> u16 {
    if mode & WRITE_BITS == 0 { attr | ATTR_READONLY } else { attr & !ATTR_READONLY }
}

/// Whether an entry is hidden, which the mount may choose not to list.
/// # C: O(1)
pub fn is_hidden(attr: u16) -> bool { attr & ATTR_HIDDEN != 0 }

/// Whether an entry carries the system attribute. # C: O(1)
pub fn is_system(attr: u16) -> bool { attr & ATTR_SYSTEM != 0 }

/// The attribute word after a write, which marks the file changed.
/// # C: O(1)
pub fn mark_archived(attr: u16) -> u16 { attr | ATTR_ARCHIVE }
