//! What a volume's feature word means for this mount.
//!
//! Three answers, and the difference between them is what a wrong one costs:
//!
//! - **Mount.** The bit changes nothing this build reads, or names something
//!   it reads correctly.
//! - **Read-only.** The bit is readable but not writable here, so the mount
//!   proceeds and refuses writes — which is what the reference does for a
//!   volume marked read-only at format time.
//! - **Refuse.** The bit changes how bytes are laid out or how a name
//!   resolves, and this build would produce wrong answers with no error. A
//!   filesystem that misreads is worse than one that refuses.
//!
//! An UNRECOGNISED bit is IGNORED, which is what the reference does. This
//! filesystem's feature word is not an incompatibility mask: every bit that
//! changes how bytes are laid out or how a name resolves is one of the bits
//! named below, and each is judged on its own. Refusing a volume for a bit
//! that means nothing here would refuse filesystems that read perfectly.

use crate::flags::*;

/// What this mount may do with a volume, once its features are read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Access {
    /// Both directions.
    ReadWrite,
    /// Reads only, and the superblock says so.
    ReadOnly,
}

/// Why a volume was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// Names resolve through a case-folding table this build cannot load, so
    /// a lookup would miss names that exist.
    Casefold,
}

/// Every bit this build recognises. Nothing is refused for being outside it;
/// the set records what has been considered.
pub const KNOWN: u32 = FEATURE_ENCRYPT
    | FEATURE_BLKZONED
    | FEATURE_ATOMIC_WRITE
    | FEATURE_EXTRA_ATTR
    | FEATURE_PRJQUOTA
    | FEATURE_INODE_CHKSUM
    | FEATURE_FLEXIBLE_INLINE_XATTR
    | FEATURE_QUOTA_INO
    | FEATURE_INODE_CRTIME
    | FEATURE_LOST_FOUND
    | FEATURE_VERITY
    | FEATURE_SB_CHKSUM
    | FEATURE_CASEFOLD
    | FEATURE_COMPRESSION
    | FEATURE_RO
    | FEATURE_DEVICE_ALIAS
    | FEATURE_PACKED_SSA;

/// Decide what `feature` permits.
///
/// Spanning several devices, aliasing one, and being laid out for a drive's
/// zones are NOT refusals: each changes where a block lives or how a segment
/// is filled, and each is answered by the module that owns that question
/// (`devices`, `zoned`) rather than by declining the volume.
/// # C: O(1)
pub fn access(feature: u32) -> Result<Access, Refusal> {
    if feature & FEATURE_RO != 0 { return Ok(Access::ReadOnly); }
    Ok(Access::ReadWrite)
}

/// Whether the volume's blocks are laid out for a drive's zones. # C: O(1)
pub fn has_blkzoned(feature: u32) -> bool { feature & FEATURE_BLKZONED != 0 }

/// Whether a file on the volume may stand for a whole member device.
/// # C: O(1)
pub fn has_device_alias(feature: u32) -> bool { feature & FEATURE_DEVICE_ALIAS != 0 }

/// Whether inode checksums are stored and therefore checkable. # C: O(1)
pub fn has_inode_chksum(feature: u32) -> bool { feature & FEATURE_INODE_CHKSUM != 0 }

/// Whether the superblock carries its own checksum. # C: O(1)
pub fn has_sb_chksum(feature: u32) -> bool { feature & FEATURE_SB_CHKSUM != 0 }

/// Whether inodes may carry the extra attribute region. # C: O(1)
pub fn has_extra_attr(feature: u32) -> bool { feature & FEATURE_EXTRA_ATTR != 0 }

/// Whether an inode states its own inline-attribute reservation, rather than
/// taking the fixed default. # C: O(1)
pub fn has_flexible_inline_xattr(feature: u32) -> bool {
    feature & FEATURE_FLEXIBLE_INLINE_XATTR != 0
}

/// Whether inodes may carry a creation time. # C: O(1)
pub fn has_inode_crtime(feature: u32) -> bool { feature & FEATURE_INODE_CRTIME != 0 }

/// Whether project ids are stored. # C: O(1)
pub fn has_project_quota(feature: u32) -> bool { feature & FEATURE_PRJQUOTA != 0 }

/// Whether the volume keeps its quota files as ordinary inodes named by the
/// superblock, rather than by mount option. # C: O(1)
pub fn has_quota_ino(feature: u32) -> bool { feature & FEATURE_QUOTA_INO != 0 }

/// Whether names on this volume resolve case-insensitively. # C: O(1)
pub fn has_casefold(feature: u32) -> bool { feature & FEATURE_CASEFOLD != 0 }

/// Whether the volume records a hash tree for any file. # C: O(1)
pub fn has_verity(feature: u32) -> bool { feature & FEATURE_VERITY != 0 }

/// Whether any file on the volume may be stored compressed. # C: O(1)
pub fn has_compression(feature: u32) -> bool { feature & FEATURE_COMPRESSION != 0 }

/// Whether any file on the volume may be stored encrypted. # C: O(1)
pub fn has_encrypt(feature: u32) -> bool { feature & FEATURE_ENCRYPT != 0 }

#[cfg(test)]
#[path = "tests/features.rs"]
mod tests;
