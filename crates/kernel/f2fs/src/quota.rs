//! Quota accounting: who is using how much, and what they are allowed.
//!
//! The superblock names up to three inodes, one per kind of identity. Each is
//! an ordinary file whose CONTENTS are a format this filesystem does not
//! define — a radix tree keyed by the identity, with one record per identity
//! at its leaves. Nothing here reads a medium: a quota file is a byte slice,
//! which is what makes the walk and the limit decision testable without one.
//!
//! Three things are easy to get wrong and each is silent:
//!
//! - The two space limits are stored in units of a thousand and twenty-four
//!   bytes while usage beside them is stored in bytes (`dqblk`).
//! - A limit of zero means unlimited, and a soft limit is a clock rather than
//!   a refusal (`limit`).
//! - A mount option asks for ENFORCEMENT; whether a kind is accounted at all
//!   is the superblock's answer, not the option's (`types`).
//!
//! Module manifest:
//! - `uapi`:   the on-disk numbers, offsets and widths.
//! - `info`:   the two headers, and the tree shape they imply.
//! - `dqblk`:  one identity's record, in both revisions.
//! - `tree`:   finding, reading and rewriting a record by identity.
//! - `limit`:  whether an allocation fits, and what it does to the record.
//! - `types`:  which kinds a volume offers this mount.

use syscall::errno::Errno;

pub mod uapi;
pub mod info;
pub mod dqblk;
pub mod tree;
pub mod limit;
pub mod types;

pub use dqblk::Dqblk;
pub use info::{Info, Revision};
pub use limit::{Ask, Verdict};
pub use types::{Enforcement, Setup};

/// Why a quota file could not be used.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum QuotaError {
    /// The file ends inside a structure that was supposed to be there.
    Truncated,
    /// The magic names a different kind, or no kind at all.
    BadMagic,
    /// A revision this build does not read.
    BadVersion,
    /// A kind outside the three that exist.
    BadKind,
    /// The header claims more blocks than the file holds.
    BlocksPastEnd,
    /// A reference points outside the blocks the header describes.
    BlockOutOfRange,
    /// A leaf claims more records than one can hold, or claims to hold none
    /// while a record is being taken out of it.
    BadEntryCount,
    /// A leaf offered as having a slot spare has none.
    BlockFull,
    /// The tree is deeper than this build will walk.
    DepthTooBig,
    /// A block on the path points back to one already on it.
    Cycle,
    /// The tree has no root block at all.
    NoRoot,
    /// The tree led to a leaf that does not hold the record it claimed.
    DanglingLeaf,
    /// The identity has no record, and this operation needed one.
    NoEntry,
    /// A limit too wide for the revision's field to hold.
    LimitTooWide,
    /// Project accounting was asked for on a volume that does not store
    /// project identities.
    NoProjectQuota,
    /// A quota file was named by something that cannot name one: nothing, or
    /// a path rather than a name in the volume's root.
    BadQuotaName,
    /// One kind's file was named by the mount while another was asked for out
    /// of the superblock. The two are different files in different formats.
    MixedQuotaFormats,
    /// A quota file was named without saying what format its records are in.
    NoJournalledFormat,
}

impl QuotaError {
    /// What a caller reports for this. A structurally impossible file is
    /// unclean rather than an I/O error; a tree that contradicts itself is
    /// reported the way the reference reports it, as a failed read.
    /// # C: O(1)
    pub fn errno(self) -> Errno {
        match self {
            QuotaError::BadMagic | QuotaError::BadVersion | QuotaError::BadKind => Errno::Einval,
            QuotaError::NoProjectQuota => Errno::Einval,
            QuotaError::BadQuotaName => Errno::Einval,
            QuotaError::MixedQuotaFormats => Errno::Einval,
            QuotaError::NoJournalledFormat => Errno::Einval,
            QuotaError::LimitTooWide => Errno::Erange,
            QuotaError::NoEntry => Errno::Enoent,
            QuotaError::Cycle | QuotaError::DanglingLeaf | QuotaError::DepthTooBig => Errno::Eio,
            QuotaError::BlockFull => Errno::Eio,
            _ => Errno::Euclean,
        }
    }
}

#[cfg(test)]
#[path = "tests/quota.rs"]
mod tests;
