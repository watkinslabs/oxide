//! The two enumerations the superblock's arrays are indexed by.
//!
//! The numbers are the ABI. A checker built against a different release
//! decodes the same bytes, so a value may be appended and never reordered:
//! renumbering turns every recorded error on every existing volume into a
//! different error, silently.

/// Bytes the error bitmap occupies, which bounds the kinds it can record.
pub const MAX_F2FS_ERRORS: usize = 16;
/// Bytes the stop-reason array occupies, one saturating count per reason.
pub const MAX_STOP_REASON: usize = 32;

/// A kind of inconsistency found on the medium.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Error {
    CorruptedCluster = 0,
    FailDecompression = 1,
    InvalidBlkaddr = 2,
    CorruptedDirent = 3,
    CorruptedInode = 4,
    InconsistentSummary = 5,
    InconsistentFooter = 6,
    InconsistentSumType = 7,
    CorruptedJournal = 8,
    InconsistentNodeCount = 9,
    InconsistentBlockCount = 10,
    InvalidCurseg = 11,
    InconsistentSit = 12,
    CorruptedVerityXattr = 13,
    CorruptedXattr = 14,
    InvalidNodeReference = 15,
    InconsistentNat = 16,
    InconsistentOrphan = 17,
}

/// One past the last kind, which is the width the bitmap must cover.
pub const ERROR_MAX: usize = 18;

impl Error {
    /// Which bit of the bitmap this kind occupies. # C: O(1)
    pub fn bit(self) -> usize { self as usize }

    /// Every kind, so a caller can walk the set without knowing its size.
    /// # C: O(1)
    pub const ALL: [Error; ERROR_MAX] = [
        Error::CorruptedCluster, Error::FailDecompression, Error::InvalidBlkaddr,
        Error::CorruptedDirent, Error::CorruptedInode, Error::InconsistentSummary,
        Error::InconsistentFooter, Error::InconsistentSumType, Error::CorruptedJournal,
        Error::InconsistentNodeCount, Error::InconsistentBlockCount, Error::InvalidCurseg,
        Error::InconsistentSit, Error::CorruptedVerityXattr, Error::CorruptedXattr,
        Error::InvalidNodeReference, Error::InconsistentNat, Error::InconsistentOrphan,
    ];

    /// Whether this kind means the medium itself disagrees with itself, rather
    /// than one file being unreadable.
    ///
    /// The distinction is what a caller reports upwards: a structural
    /// disagreement is a filesystem-level fault a monitor must see, while a
    /// cluster that will not decompress is one file's problem.
    /// # C: O(1)
    pub fn is_metadata(self) -> bool {
        matches!(self,
            Error::InvalidBlkaddr | Error::CorruptedInode | Error::InconsistentSummary
            | Error::InconsistentSumType | Error::CorruptedJournal
            | Error::InconsistentNodeCount | Error::InconsistentBlockCount
            | Error::InvalidCurseg | Error::InconsistentSit | Error::InvalidNodeReference
            | Error::InconsistentNat)
    }
}

/// Why a mount stopped writing checkpoints.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum StopReason {
    /// Asked for, rather than found: the volume was shut down deliberately.
    Shutdown = 0,
    FaultInject = 1,
    MetaPage = 2,
    WriteFail = 3,
    CorruptedSummary = 4,
    UpdateInode = 5,
    FlushFail = 6,
    NoSegment = 7,
    CorruptedFreeBitmap = 8,
    CorruptedNid = 9,
    ReadMeta = 10,
    ReadNode = 11,
    ReadData = 12,
}

/// One past the last reason.
pub const STOP_REASON_MAX: usize = 13;

impl StopReason {
    /// Which slot of the array counts this reason. # C: O(1)
    pub fn slot(self) -> usize { self as usize }
}
