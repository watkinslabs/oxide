//! Names: UTF-16 on the medium, UTF-8 at the interface, and a hash that makes
//! a lookup cheap.
//!
//! A name is stored as UTF-16 units spread fifteen at a time across as many
//! name entries as it needs, with no length of its own — the stream entry
//! carries the length, and a name entry's trailing units past that length are
//! padding rather than characters.
//!
//! Beside the length the stream entry carries a HASH of the up-cased name.
//! That is what makes a lookup cheap: a candidate whose hash differs cannot be
//! the name being looked for, so its name entries never have to be read. The
//! hash is not a decision — a match still compares the whole name — but a
//! wrong hash makes a file unfindable while it sits in the directory.

use alloc::string::String;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::checksum;
use crate::uapi::{MAX_NAME_LENGTH, NAME_CHARS_PER_ENTRY};
use crate::upcase::UpCase;

/// Characters a name may not contain, whatever the medium would accept.
///
/// The slash is the path separator, so a name containing one could never be
/// reached; the rest are refused by the format itself.
const FORBIDDEN: &[u16] = &[
    0x0022, // "
    0x002A, // *
    0x002F, // /
    0x003A, // :
    0x003C, // <
    0x003E, // >
    0x003F, // ?
    0x005C, // backslash
    0x007C, // |
];

/// A name as the medium holds it, with what a lookup needs precomputed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UniName {
    pub units: Vec<u16>,
    pub hash: u16,
}

impl UniName {
    /// Length in UTF-16 units, which is what the stream entry records.
    /// # C: O(1)
    pub fn len(&self) -> usize { self.units.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.units.is_empty() }
}

/// What a name is being resolved FOR.
///
/// The two are not symmetric, and the asymmetry is deliberate. A name being
/// LOOKED UP is allowed to contain characters the format refuses, because a
/// medium another system wrote may hold such a name and it must still be
/// findable; a name being CREATED is refused, because writing one makes a file
/// no other system can address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Usage { Lookup, Create }

/// Encode a name for this volume.
///
/// The hash is taken over the UP-CASED units, so a lookup spelled in any case
/// produces the hash the entry recorded.
///
/// Trailing dots are removed unless the mount asked to keep them; a mount that
/// did may still not CREATE such a name, only find one that is already there,
/// because Windows cannot address it.
/// # C: O(name bytes)
pub fn resolve(upcase: &UpCase, name: &str, keep_last_dots: bool, usage: Usage)
    -> Result<UniName, Errno> {
    let stripped = name.trim_end_matches('.');
    let name = if keep_last_dots {
        if usage == Usage::Create && stripped.len() < name.len() { return Err(Errno::Einval); }
        name
    } else {
        stripped
    };
    if name.is_empty() { return Err(Errno::Enoent); }
    let units: Vec<u16> = name.encode_utf16().collect();
    if units.len() > MAX_NAME_LENGTH { return Err(Errno::Enametoolong); }
    let lossy = units.iter().any(|u| *u < 0x0020 || FORBIDDEN.contains(u));
    if lossy && usage == Usage::Create { return Err(Errno::Einval); }
    let hash = checksum::name_hash(&upcase.fold_name(&units));
    Ok(UniName { units, hash })
}

/// Encode a name being created, under a mount that strips trailing dots.
/// # C: O(name bytes)
pub fn encode(upcase: &UpCase, name: &str) -> Result<UniName, Errno> {
    resolve(upcase, name, false, Usage::Create)
}

/// The hash a name would have on this volume, without building the name.
/// # C: O(name.len())
pub fn hash_of(upcase: &UpCase, units: &[u16]) -> u16 {
    checksum::name_hash(&upcase.fold_name(units))
}

/// Decode stored units into a string.
///
/// Unpaired surrogates are replaced rather than refused: a medium another
/// system wrote can carry them, and refusing makes the whole directory
/// unreadable instead of one name odd-looking.
/// # C: O(units.len())
pub fn decode(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Name entries a name of `len` units occupies. # C: O(1)
pub fn name_entries(len: usize) -> usize { len.div_ceil(NAME_CHARS_PER_ENTRY) }

/// Entries a whole set for a name of `len` units occupies: the file entry, the
/// stream entry, and the name entries. # C: O(1)
pub fn entry_count(len: usize) -> Result<usize, Errno> {
    if len == 0 || len > MAX_NAME_LENGTH { return Err(Errno::Einval); }
    Ok(crate::uapi::ES_IDX_FIRST_NAME + name_entries(len))
}

/// Whether two names are the same name on this volume. # C: O(shorter name)
pub fn eq(upcase: &UpCase, a: &[u16], b: &[u16]) -> bool { upcase.eq(a, b) }

#[cfg(test)]
#[path = "tests/name.rs"]
mod tests;
