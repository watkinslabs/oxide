//! Building the long-name slots: the encode side of what `dirent` decodes.
//!
//! A long name is stored in the records that PRECEDE its short entry, in
//! reverse: the slot written first carries the LAST thirteen characters and
//! the highest ordinal, and the run's first slot on disk is the one marked
//! LAST. Every slot repeats the checksum of the short name it belongs to, so
//! a reader can tell a run that names this entry from a run some other system
//! left behind.
//!
//! The padding is part of the format, not slack: a name that does not fill
//! its last slot is terminated with one NUL and the remainder filled with
//! 0xFFFF, and a name that fills it exactly gets neither.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::dirent::{ATTR_EXT, CHARS_PER_SLOT, ENTRY_BYTES, LAST_LONG_ENTRY};
use super::flags::MAX_LONG_NAME;

/// Byte offsets within a long-name slot.
mod slot {
    pub const ORDINAL: usize = 0;
    pub const CHARS_0: usize = 1;
    pub const CHARS_0_LEN: usize = 10;
    pub const ATTR: usize = 11;
    pub const RESERVED: usize = 12;
    pub const CHECKSUM: usize = 13;
    pub const CHARS_1: usize = 14;
    pub const CHARS_1_LEN: usize = 12;
    pub const START: usize = 26;
    pub const CHARS_2: usize = 28;
    pub const CHARS_2_LEN: usize = 4;
}

/// Terminator written after the last character of a partly-filled slot.
const NAME_TERMINATOR: u16 = 0x0000;
/// Filler after that terminator.
const NAME_PADDING: u16 = 0xffff;

/// A name as the code units the slots store, already padded to whole slots.
///
/// `len` is the name's own length; the vector is longer whenever the name did
/// not fill its last slot.
pub struct Encoded {
    pub units: Vec<u16>,
    pub len: usize,
}

impl Encoded {
    /// Slots this name needs. # C: O(1)
    pub fn slots(&self) -> usize { self.units.len() / CHARS_PER_SLOT }
}

/// A name's code units, padded to whole slots.
///
/// `ENAMETOOLONG` past what the slots can address — the ordinal is five bits
/// wide and each slot holds thirteen, so nothing longer can be stored, let
/// alone found again. Counted in CODE UNITS, so a name of characters outside
/// the basic plane reaches the limit at half as many characters, which is
/// what the format actually constrains.
/// # C: O(name length)
pub fn encode(name: &str) -> Result<Encoded, Errno> {
    encode_units(&name.encode_utf16().collect::<Vec<u16>>())
}

/// Encode already-decoded UTF-16 units, including units produced by
/// `uni_xlate` input escapes. # C: O(name length)
pub fn encode_units(input: &[u16]) -> Result<Encoded, Errno> {
    let mut units = input.to_vec();
    if units.is_empty() { return Err(Errno::Enoent); }
    if units.len() > MAX_LONG_NAME { return Err(Errno::Enametoolong); }
    let len = units.len();
    if len % CHARS_PER_SLOT != 0 {
        units.push(NAME_TERMINATOR);
        let fill = (CHARS_PER_SLOT - units.len() % CHARS_PER_SLOT) % CHARS_PER_SLOT;
        units.resize(units.len() + fill, NAME_PADDING);
    }
    Ok(Encoded { units, len })
}

/// Decode Linux's `uni_xlate` input spelling (`:XXXX`) into the UTF-16 units
/// stored by FAT. A malformed escape is an invalid name, never literal text.
/// # C: O(name length)
pub fn input_units(name: &str) -> Result<Vec<u16>, Errno> {
    let bytes = name.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b':' {
            if at + 5 > bytes.len() { return Err(Errno::Einval); }
            let mut unit = 0u16;
            for &byte in &bytes[at + 1..at + 5] {
                let digit = match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => return Err(Errno::Einval),
                };
                unit = (unit << 4) | u16::from(digit);
            }
            out.push(unit);
            at += 5;
        } else {
            let ch = name[at..].chars().next().ok_or(Errno::Einval)?;
            let mut encoded = [0u16; 2];
            let encoded = ch.encode_utf16(&mut encoded);
            out.extend(encoded.iter().copied());
            at += ch.len_utf8();
        }
    }
    Ok(out)
}

/// The slot records for an encoded name, in the order they are written to
/// disk.
///
/// The first record returned is the one marked LAST and carrying the highest
/// ordinal, because the run is stored backwards. The short entry those slots
/// name goes immediately after the last record returned.
/// # C: O(slots)
pub fn build_slots(encoded: &Encoded, checksum: u8) -> Vec<[u8; ENTRY_BYTES]> {
    let count = encoded.slots();
    let mut out = Vec::with_capacity(count);
    for ordinal in (1..=count).rev() {
        let mut r = [0u8; ENTRY_BYTES];
        let mut id = ordinal as u8;
        if ordinal == count { id |= LAST_LONG_ENTRY; }
        r[slot::ORDINAL] = id;
        r[slot::ATTR] = ATTR_EXT;
        r[slot::RESERVED] = 0;
        r[slot::CHECKSUM] = checksum;
        // The cluster field is where an old reader looks for a file's data.
        // Zero is what tells it this record names nothing.
        r[slot::START] = 0;
        r[slot::START + 1] = 0;
        let base = (ordinal - 1) * CHARS_PER_SLOT;
        let mut at = base;
        for (start, len) in [(slot::CHARS_0, slot::CHARS_0_LEN),
                             (slot::CHARS_1, slot::CHARS_1_LEN),
                             (slot::CHARS_2, slot::CHARS_2_LEN)] {
            for i in (0..len).step_by(2) {
                r[start + i..start + i + 2].copy_from_slice(&encoded.units[at].to_le_bytes());
                at += 1;
            }
        }
        out.push(r);
    }
    out
}
