//! The up-case table: the volume's own answer to "which two names are the
//! same name".
//!
//! exFAT does not define case folding — the VOLUME does. Every name comparison
//! and every name hash goes through the table the medium carries, so a volume
//! formatted by one system and read by another agrees about which names
//! collide. Substituting a different rule makes a lookup miss a file that is
//! there, and makes a create succeed where the volume already has that name.
//!
//! The stored form is run-length compressed: a unit equal to the index it
//! would occupy is an identity entry, the marker `0xFFFF` introduces a count
//! of identity entries to skip, and anything else is a mapping. The table is
//! accepted only when it expands to the whole 16-bit range AND its checksum
//! matches the one the directory entry recorded — a half-read table maps the
//! characters it reached and leaves the rest identity, which silently changes
//! which names collide.
//!
//! Module manifest:
//! - `default`: the table used by a volume that carries none of its own.

use alloc::vec::Vec;

use crate::checksum;
use crate::uapi::{UPCASE_ENTRIES, UPCASE_SKIP_MARKER};

pub mod default;

/// A volume's case-folding answer.
///
/// Stored as the reference stores it: a zero means "this character is its own
/// upper case", so the common identity case costs no entry of its own.
pub struct UpCase {
    table: Vec<u16>,
}

/// Why a stored table was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpCaseError {
    /// The compressed form ended before covering the whole range.
    Incomplete,
    /// The bytes do not sum to the checksum the entry recorded.
    BadChecksum,
}

impl UpCase {
    /// The upper case of one UTF-16 unit. # C: O(1)
    pub fn fold(&self, unit: u16) -> u16 {
        let mapped = self.table[unit as usize];
        if mapped == 0 { unit } else { mapped }
    }

    /// A name folded for comparison and hashing. # C: O(name.len())
    pub fn fold_name(&self, name: &[u16]) -> Vec<u16> {
        name.iter().map(|u| self.fold(*u)).collect()
    }

    /// Whether two names are the same name on this volume.
    /// # C: O(shorter name)
    pub fn eq(&self, a: &[u16], b: &[u16]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| self.fold(*x) == self.fold(*y))
    }

    /// The table as raw mappings, where zero means identity. # C: O(1)
    pub fn raw(&self) -> &[u16] { &self.table }
}

/// Expand a stored table.
///
/// `expected` is the checksum the up-case directory entry recorded, over the
/// table's bytes as they sit on the medium. Both conditions must hold: a table
/// that covers the range with the wrong bytes is a different fold, and a table
/// with the right checksum that stopped early was truncated in transit.
/// # C: O(table bytes)
pub fn load(bytes: &[u8], expected: u32) -> Result<UpCase, UpCaseError> {
    let mut table = alloc::vec![0u16; UPCASE_ENTRIES];
    let mut index: usize = 0;
    let mut skipping = false;
    for pair in bytes.chunks_exact(2) {
        if index > UPCASE_ENTRIES - 1 { break; }
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if skipping {
            index += unit as usize;
            skipping = false;
        } else if unit as usize == index {
            index += 1;
        } else if unit == UPCASE_SKIP_MARKER {
            skipping = true;
        } else {
            table[index] = unit;
            index += 1;
        }
    }
    if index < UPCASE_ENTRIES - 1 { return Err(UpCaseError::Incomplete); }
    if checksum::sum32(bytes, 0) != expected { return Err(UpCaseError::BadChecksum); }
    Ok(UpCase { table })
}

/// The table a volume that carries none of its own is read with.
///
/// A volume without an up-case entry is malformed — every formatter writes one
/// — so this is a recovery path rather than a normal one, and it is the
/// reference's behaviour: refuse nothing, fold by the built-in rules.
/// # C: O(UPCASE_ENTRIES)
pub fn builtin() -> UpCase { UpCase { table: default::table() } }

/// A table's compressed form, as a formatter would write it.
///
/// Exists so a test can build a volume this implementation then reads: a
/// round trip through both directions is what proves the decoder against
/// something other than itself.
/// # C: O(UPCASE_ENTRIES)
pub fn compress(table: &UpCase) -> Vec<u8> {
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < UPCASE_ENTRIES {
        if table.table[index] == 0 {
            let start = index;
            while index < UPCASE_ENTRIES && table.table[index] == 0 { index += 1; }
            let run = (index - start) as u16;
            out.extend_from_slice(&UPCASE_SKIP_MARKER.to_le_bytes());
            out.extend_from_slice(&run.to_le_bytes());
        } else {
            out.extend_from_slice(&table.table[index].to_le_bytes());
            index += 1;
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/upcase.rs"]
mod tests;
