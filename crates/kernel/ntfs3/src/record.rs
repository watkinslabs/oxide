//! An MFT record: the header, and the attributes it carries.
//!
//! Everything on this filesystem is a record in one table. A file is a record,
//! a directory is a record, and the table itself is a record — which is what
//! makes mounting circular: the MFT's own extent list has to be read out of
//! the first MFT record before the rest of the table can be reached at all.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::uapi::*;

/// One MFT record's header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecordHeader {
    pub sequence: u16,
    pub hard_links: u16,
    /// Offset of the first attribute.
    pub attr_off: u16,
    pub flags: u16,
    /// Bytes of the record actually used.
    pub used: u32,
    /// Bytes the record occupies.
    pub total: u32,
    /// The record of the directory holding this one, and its sequence.
    pub parent: Reference,
    pub next_attr_id: u16,
    pub record_number: u32,
}

/// A reference to another record: its number and the sequence it had when the
/// reference was made.
///
/// The sequence is what makes a stale reference detectable. A record number
/// alone is reused the moment the record is; a reference carrying the old
/// sequence names a file that no longer exists rather than whichever file took
/// its place.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Reference {
    pub number: u64,
    pub sequence: u16,
}

impl RecordHeader {
    /// Whether this record is live. # C: O(1)
    pub fn in_use(&self) -> bool { self.flags & RECORD_FLAG_IN_USE != 0 }

    /// Whether this record is a directory. # C: O(1)
    pub fn is_dir(&self) -> bool { self.flags & RECORD_FLAG_DIR != 0 }

    /// Whether this record is a BASE record rather than an extension of
    /// another. # C: O(1)
    pub fn is_base(&self) -> bool { self.parent.number == 0 && self.parent.sequence == 0 }
}

/// Why a record was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordError {
    /// Fewer bytes than a record header.
    TooShort,
    /// The signature is not a file record.
    NotFile,
    /// The record is marked as damaged by a check.
    Bad,
    /// The header's own lengths do not fit the bytes.
    Corrupt,
}

impl RecordError {
    /// # C: O(1)
    pub fn errno(self) -> Errno { Errno::Eio }
}

/// Read one 16-bit field. # C: O(1)
fn le16(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }

/// Read one 32-bit field. # C: O(1)
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Decode a reference. # C: O(1)
pub fn reference(bytes: &[u8], at: usize) -> Reference {
    Reference {
        number: u64::from(le32(bytes, at)) | (u64::from(le16(bytes, at + 4)) << 32),
        sequence: le16(bytes, at + 6),
    }
}

/// Lay a reference out. # C: O(1)
pub fn write_reference(bytes: &mut [u8], at: usize, r: &Reference) {
    bytes[at..at + 4].copy_from_slice(&((r.number & 0xFFFF_FFFF) as u32).to_le_bytes());
    bytes[at + 4..at + 6].copy_from_slice(&(((r.number >> 32) & 0xFFFF) as u16).to_le_bytes());
    bytes[at + 6..at + 8].copy_from_slice(&r.sequence.to_le_bytes());
}

/// Decode a record header from bytes whose update sequence has already been
/// undone.
///
/// A record still carrying its sequence bytes decodes here without error and
/// with two bytes of every sector wrong, which is why undoing the sequence is
/// the caller's first act rather than this function's.
/// # C: O(1)
pub fn parse(bytes: &[u8]) -> Result<RecordHeader, RecordError> {
    if bytes.len() < MFT_OFF_RECORD_NUM + 4 { return Err(RecordError::TooShort); }
    let sign = &bytes[REC_OFF_SIGN..REC_OFF_SIGN + 4];
    if sign == SIG_BAAD.as_slice() { return Err(RecordError::Bad); }
    if sign != SIG_FILE.as_slice() { return Err(RecordError::NotFile); }
    let header = RecordHeader {
        sequence: le16(bytes, MFT_OFF_SEQ),
        hard_links: le16(bytes, MFT_OFF_HARD_LINKS),
        attr_off: le16(bytes, MFT_OFF_ATTR_OFF),
        flags: le16(bytes, MFT_OFF_FLAGS),
        used: le32(bytes, MFT_OFF_USED),
        total: le32(bytes, MFT_OFF_TOTAL),
        parent: reference(bytes, MFT_OFF_PARENT_REF),
        next_attr_id: le16(bytes, MFT_OFF_NEXT_ATTR_ID),
        record_number: le32(bytes, MFT_OFF_RECORD_NUM),
    };
    // The attributes must begin inside the record and the used length must not
    // exceed the bytes there are, or every walk below runs off the end.
    if usize::from(header.attr_off) >= bytes.len() { return Err(RecordError::Corrupt); }
    if header.used as usize > bytes.len() { return Err(RecordError::Corrupt); }
    if header.used < u32::from(header.attr_off) { return Err(RecordError::Corrupt); }
    Ok(header)
}

/// Where each attribute of a record begins, in order.
///
/// The walk stops at the end marker, at the used length, or at the first
/// header whose own size cannot be part of this record — a size of zero would
/// otherwise loop forever, and one too large would read the next record's
/// bytes as this record's attribute.
/// # C: O(attributes)
pub fn attribute_offsets(bytes: &[u8], header: &RecordHeader) -> Vec<usize> {
    let mut out = Vec::new();
    let limit = core::cmp::min(header.used as usize, bytes.len());
    let mut at = header.attr_off as usize;
    while at + 8 <= limit {
        let ty = le32(bytes, at);
        if ty == ATTR_END { break; }
        let size = le32(bytes, at + ATTR_OFF_SIZE) as usize;
        if size < 8 || at + size > limit { break; }
        out.push(at);
        at += size;
    }
    out
}

/// Set the record's used length and reseal nothing else.
///
/// The caller reseals the update sequence; this only records how much of the
/// record is meaningful, which every reader clamps its walk to.
/// # C: O(1)
pub fn set_used(bytes: &mut [u8], used: u32) {
    bytes[MFT_OFF_USED..MFT_OFF_USED + 4].copy_from_slice(&used.to_le_bytes());
}

/// Set the record's flags. # C: O(1)
pub fn set_flags(bytes: &mut [u8], flags: u16) {
    bytes[MFT_OFF_FLAGS..MFT_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
}

/// Set the record's sequence number. # C: O(1)
pub fn set_sequence(bytes: &mut [u8], sequence: u16) {
    bytes[MFT_OFF_SEQ..MFT_OFF_SEQ + 2].copy_from_slice(&sequence.to_le_bytes());
}

/// Set the record's hard-link count. # C: O(1)
pub fn set_hard_links(bytes: &mut [u8], links: u16) {
    bytes[MFT_OFF_HARD_LINKS..MFT_OFF_HARD_LINKS + 2].copy_from_slice(&links.to_le_bytes());
}

/// The sequence a record takes when it is reused.
///
/// It advances on every reuse and never lands on zero, which is what a
/// reference uses to mean "no reference at all".
/// # C: O(1)
pub fn next_sequence(current: u16) -> u16 {
    match current.wrapping_add(1) { 0 => 1, next => next }
}

/// Build an empty record of `size` bytes, ready for attributes.
///
/// The fixup array is placed and counted here, because its width depends on
/// the record's size and a record whose array is too short leaves the last
/// sector's tail unprotected.
/// # C: O(size)
pub fn format(size: u32, number: u64, sequence: u16) -> Vec<u8> {
    let mut out = alloc::vec![0u8; size as usize];
    out[REC_OFF_SIGN..REC_OFF_SIGN + 4].copy_from_slice(SIG_FILE.as_slice());
    let fix_off = MFT_FIXUP_OFFSET_SMALL;
    let fix_num = (size >> SECTOR_SHIFT) as u16 + 1;
    out[REC_OFF_FIX_OFF..REC_OFF_FIX_OFF + 2].copy_from_slice(&fix_off.to_le_bytes());
    out[REC_OFF_FIX_NUM..REC_OFF_FIX_NUM + 2].copy_from_slice(&fix_num.to_le_bytes());
    // Attributes begin after the fixup array, eight-byte aligned.
    let attr_off = (usize::from(fix_off) + usize::from(fix_num) * 2).next_multiple_of(8) as u16;
    out[MFT_OFF_ATTR_OFF..MFT_OFF_ATTR_OFF + 2].copy_from_slice(&attr_off.to_le_bytes());
    set_sequence(&mut out, sequence);
    set_hard_links(&mut out, 1);
    set_flags(&mut out, RECORD_FLAG_IN_USE);
    out[MFT_OFF_TOTAL..MFT_OFF_TOTAL + 4].copy_from_slice(&size.to_le_bytes());
    out[MFT_OFF_NEXT_ATTR_ID..MFT_OFF_NEXT_ATTR_ID + 2].copy_from_slice(&1u16.to_le_bytes());
    out[MFT_OFF_RECORD_NUM..MFT_OFF_RECORD_NUM + 4]
        .copy_from_slice(&(number as u32).to_le_bytes());
    // The end marker, and the used length that stops at it.
    let end = attr_off as usize;
    out[end..end + 4].copy_from_slice(&ATTR_END.to_le_bytes());
    set_used(&mut out, attr_off as u32 + 8);
    out
}

#[cfg(test)]
#[path = "tests/record.rs"]
mod tests;
