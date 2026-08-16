//! The update sequence: how NTFS tells a torn write from a whole one.
//!
//! Every multi-sector structure — an MFT record, an index buffer — has the
//! LAST TWO BYTES of each of its sectors replaced by one repeated value before
//! it is written, and the bytes those replaced are kept in an array at the
//! front. A reader checks that every sector still ends in that value: if one
//! does not, that sector came from a different write than the rest and the
//! structure is torn.
//!
//! Undoing this is not optional and not cosmetic. Skipping it leaves two bytes
//! of every 512 holding the sequence number instead of the record's own data —
//! an attribute header's length field, an index entry's size — so the record
//! decodes into nonsense that looks structurally plausible.

use syscall::errno::Errno;

use crate::uapi::{REC_OFF_FIX_NUM, REC_OFF_FIX_OFF, SECTOR_BYTES};

/// Why a structure's update sequence was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FixupError {
    /// The array's position or count cannot describe this structure.
    Corrupt,
    /// A sector does not end in the sequence value: the write was torn.
    Torn,
}

impl FixupError {
    /// # C: O(1)
    pub fn errno(self) -> Errno { Errno::Eio }
}

/// Read one 16-bit field. # C: O(1)
fn le16(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }

/// Where the array sits and how many entries it has, checked against the
/// structure's length.
///
/// `simple` is for a structure whose count is derived from its length rather
/// than read — the reference does that where the header's own count cannot be
/// trusted yet.
/// # C: O(1)
fn locate(bytes: &[u8], simple: bool) -> Result<(usize, usize), FixupError> {
    if bytes.len() < REC_OFF_FIX_NUM + 2 { return Err(FixupError::Corrupt); }
    let fo = le16(bytes, REC_OFF_FIX_OFF) as usize;
    let fn_ = if simple { (bytes.len() >> crate::uapi::SECTOR_SHIFT) + 1 }
              else { le16(bytes, REC_OFF_FIX_NUM) as usize };
    // The array must be aligned, fit in the first sector, and cover exactly
    // the sectors the structure has.
    if fo & 1 != 0 { return Err(FixupError::Corrupt); }
    if fo + fn_ * 2 > SECTOR_BYTES { return Err(FixupError::Corrupt); }
    if fn_ == 0 { return Err(FixupError::Corrupt); }
    let sectors = fn_ - 1;
    if sectors * SECTOR_BYTES > bytes.len() { return Err(FixupError::Corrupt); }
    Ok((fo, sectors))
}

/// Put back the bytes the update sequence displaced.
///
/// Every sector must end in the sequence value. A sector that does not is
/// reported as torn — and the record is still un-fixed-up in place, because a
/// caller that wants to look at the damage needs the bytes.
/// # C: O(sectors)
pub fn post_read(bytes: &mut [u8], simple: bool) -> Result<(), FixupError> {
    let (fo, sectors) = locate(bytes, simple)?;
    let sample = le16(bytes, fo);
    let mut torn = false;
    for i in 0..sectors {
        let tail = (i + 1) * SECTOR_BYTES - 2;
        let replacement = le16(bytes, fo + (i + 1) * 2);
        if le16(bytes, tail) != sample { torn = true; }
        bytes[tail..tail + 2].copy_from_slice(&replacement.to_le_bytes());
    }
    if torn { return Err(FixupError::Torn); }
    Ok(())
}

/// Take the bytes the update sequence must displace, and stamp the sequence
/// value in their place.
///
/// The value is advanced by the caller, not here: it belongs to the structure
/// and must differ from the last write's, or a torn write between two
/// identical sequences reads as whole.
/// # C: O(sectors)
pub fn pre_write(bytes: &mut [u8], sample: u16) -> Result<(), FixupError> {
    let (fo, sectors) = locate(bytes, false)?;
    bytes[fo..fo + 2].copy_from_slice(&sample.to_le_bytes());
    for i in 0..sectors {
        let tail = (i + 1) * SECTOR_BYTES - 2;
        let saved = le16(bytes, tail);
        let slot = fo + (i + 1) * 2;
        bytes[slot..slot + 2].copy_from_slice(&saved.to_le_bytes());
        bytes[tail..tail + 2].copy_from_slice(&sample.to_le_bytes());
    }
    Ok(())
}

/// The sequence value a structure should be written with next.
///
/// Zero and 0xFFFF are skipped: a sector of zeros or of ones is what a device
/// returns for a block it never wrote, so either would make an unwritten
/// sector read as a whole one.
/// # C: O(1)
pub fn next_sample(current: u16) -> u16 {
    match current.wrapping_add(1) {
        0 | 0xFFFF => 1,
        next => next,
    }
}

#[cfg(test)]
#[path = "tests/fixup.rs"]
mod tests;
