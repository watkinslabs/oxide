//! What a type byte means.
//!
//! The byte is structured, not enumerated: the top bit says whether the entry
//! is in use, and the two bits below it split the space into critical and
//! benign, primary and secondary. That structure is what lets an
//! implementation skip an entry type it has never heard of — a BENIGN one may
//! be ignored, a CRITICAL one may not, and an implementation that ignores the
//! difference either loses data or refuses volumes it could have read.

use crate::uapi::*;

/// The kinds of entry this implementation acts on, and the classes it only
/// needs to classify.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind {
    /// The end of the directory: nothing follows.
    Unused,
    /// A record whose name was removed.
    Deleted,
    /// The invalid marker.
    Invalid,
    Bitmap,
    Upcase,
    VolumeLabel,
    File,
    /// A critical primary entry of a kind this implementation does not know.
    CriticalPrimary,
    Guid,
    Padding,
    AclTable,
    /// A benign primary entry of an unknown kind.
    BenignPrimary,
    Stream,
    Name,
    Acl,
    /// A critical secondary entry of an unknown kind.
    CriticalSecondary,
    VendorExt,
    VendorAlloc,
    /// A benign secondary entry of an unknown kind.
    BenignSecondary,
}

impl EntryKind {
    /// Whether this entry belongs to a set rather than standing alone.
    /// # C: O(1)
    pub fn is_secondary(self) -> bool {
        matches!(self, EntryKind::Stream | EntryKind::Name | EntryKind::Acl
                 | EntryKind::CriticalSecondary | EntryKind::VendorExt
                 | EntryKind::VendorAlloc | EntryKind::BenignSecondary)
    }

    /// Whether an implementation may ignore this entry without losing data.
    /// # C: O(1)
    pub fn is_benign(self) -> bool {
        matches!(self, EntryKind::Guid | EntryKind::Padding | EntryKind::AclTable
                 | EntryKind::BenignPrimary | EntryKind::VendorExt
                 | EntryKind::VendorAlloc | EntryKind::BenignSecondary)
    }

    /// Whether this entry can carry clusters of its own, which a deletion must
    /// then release. # C: O(1)
    pub fn holds_allocation(self) -> bool {
        matches!(self, EntryKind::VendorAlloc | EntryKind::BenignSecondary)
    }
}

/// Whether a type byte marks an entry currently in use. # C: O(1)
pub fn is_in_use(ty: u8) -> bool { ty != TYPE_UNUSED && ty & IN_USE_BIT != 0 }

/// Whether a type byte marks an entry whose name was removed.
///
/// Deletion clears the top bit and leaves the rest, which is what makes a
/// removed name still identifiable as the KIND of entry it was — and what
/// makes a nonzero byte below 0x80 a deleted entry rather than an unknown one.
/// # C: O(1)
pub fn is_deleted(ty: u8) -> bool { ty != TYPE_UNUSED && ty & IN_USE_BIT == 0 }

/// Classify a type byte. # C: O(1)
pub fn class_of(ty: u8) -> EntryKind {
    if ty == TYPE_UNUSED { return EntryKind::Unused; }
    if is_deleted(ty) { return EntryKind::Deleted; }
    if ty == TYPE_INVAL { return EntryKind::Invalid; }
    if ty < CRITICAL_PRI_MAX {
        return match ty {
            TYPE_BITMAP => EntryKind::Bitmap,
            TYPE_UPCASE => EntryKind::Upcase,
            TYPE_VOLUME => EntryKind::VolumeLabel,
            TYPE_FILE => EntryKind::File,
            _ => EntryKind::CriticalPrimary,
        };
    }
    if ty < BENIGN_PRI_MAX {
        return match ty {
            TYPE_GUID => EntryKind::Guid,
            TYPE_PADDING => EntryKind::Padding,
            TYPE_ACLTAB => EntryKind::AclTable,
            _ => EntryKind::BenignPrimary,
        };
    }
    if ty < CRITICAL_SEC_MAX {
        return match ty {
            TYPE_STREAM => EntryKind::Stream,
            TYPE_NAME => EntryKind::Name,
            TYPE_ACL => EntryKind::Acl,
            _ => EntryKind::CriticalSecondary,
        };
    }
    match ty {
        TYPE_VENDOR_EXT => EntryKind::VendorExt,
        TYPE_VENDOR_ALLOC => EntryKind::VendorAlloc,
        _ => EntryKind::BenignSecondary,
    }
}

/// The type byte a deletion leaves behind. # C: O(1)
pub fn deleted_byte(ty: u8) -> u8 { ty & !IN_USE_BIT }
