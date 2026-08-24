//! A whole directory entry set: the three kinds of entry read and written
//! together, with the checksum that ties them.
//!
//! A set is valid only as a whole. The file entry says how many entries
//! follow; the stream entry says how long the name is; the name entries carry
//! it fifteen units at a time. Every one of those three numbers can disagree
//! with the others on a damaged volume, and each disagreement is a different
//! error rather than a silently shorter name.

use alloc::vec::Vec;

use crate::checksum;
use crate::name;
use crate::time::Stamp;
use crate::uapi::*;

use super::file::{self, FileEntry};
use super::kind::{class_of, EntryKind};
use super::stream::{self, StreamEntry};

/// One name in a directory, as the medium holds it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EntrySet {
    pub file: FileEntry,
    pub stream: StreamEntry,
    /// The name, in UTF-16 units.
    pub units: Vec<u16>,
    /// Byte offset of the FIRST entry of the set within its directory.
    pub offset: u64,
    /// Entries the set occupies, benign secondary ones included.
    pub entries: usize,
}

/// Why a run of bytes was not a valid set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SetError {
    /// The bytes end before the set the file entry declared.
    Truncated,
    /// The file entry is not followed by a stream extension entry.
    NoStream,
    /// Fewer name entries than the declared length needs.
    ShortName,
    /// The recorded checksum is not the checksum of these bytes.
    BadChecksum,
    /// The declared entry count is outside what a name can occupy.
    BadCount,
    /// A critical secondary entry is not in the position its set requires.
    BadType,
}

impl EntrySet {
    /// The name as a string. # C: O(name length)
    pub fn name(&self) -> alloc::string::String { name::decode(&self.units) }

    /// Whether this set names a directory. # C: O(1)
    pub fn is_dir(&self) -> bool { self.file.is_dir() }

    /// The file's length: how much has been written, not how much is
    /// allocated. # C: O(1)
    pub fn size(&self) -> u64 { self.stream.valid_size }

    /// Byte offset of the STREAM entry, which a size or cluster update
    /// rewrites. # C: O(1)
    pub fn stream_offset(&self) -> u64 { self.offset + (ES_IDX_STREAM * DENTRY_BYTES) as u64 }
}

/// Decode the set beginning at the start of `bytes`.
///
/// `offset` is where those bytes sit in the directory, and is carried into the
/// result so an update can be written back where it came from rather than
/// searching the directory again.
/// # C: O(set entries)
pub fn parse(bytes: &[u8], offset: u64) -> Result<EntrySet, SetError> {
    let file = file::parse(bytes).ok_or(SetError::Truncated)?;
    let count = file.set_len();
    if count < ES_IDX_FIRST_NAME + 1 { return Err(SetError::BadCount); }
    let span = count * DENTRY_BYTES;
    if bytes.len() < span { return Err(SetError::Truncated); }

    let stream_at = ES_IDX_STREAM * DENTRY_BYTES;
    let stream = stream::parse(&bytes[stream_at..stream_at + DENTRY_BYTES])
        .ok_or(SetError::NoStream)?;

    let name_len = stream.name_len as usize;
    let needed = name::name_entries(name_len);
    if name_len == 0 || name_len > MAX_NAME_LENGTH { return Err(SetError::ShortName); }
    if count < ES_IDX_FIRST_NAME + needed { return Err(SetError::ShortName); }

    if class_of(bytes[stream_at]) != EntryKind::Stream { return Err(SetError::BadType); }
    for i in 0..needed {
        let at = (ES_IDX_FIRST_NAME + i) * DENTRY_BYTES;
        if class_of(bytes[at]) != EntryKind::Name { return Err(SetError::BadType); }
    }
    for i in ES_IDX_FIRST_NAME + needed..count {
        let kind = class_of(bytes[i * DENTRY_BYTES]);
        if !kind.is_secondary() || !kind.is_benign() { return Err(SetError::BadType); }
    }

    let mut units = Vec::with_capacity(name_len);
    for i in 0..needed {
        let at = (ES_IDX_FIRST_NAME + i) * DENTRY_BYTES;
        let chars = stream::parse_name(&bytes[at..at + DENTRY_BYTES])
            .ok_or(SetError::ShortName)?;
        let take = core::cmp::min(NAME_CHARS_PER_ENTRY, name_len - units.len());
        units.extend_from_slice(&chars[..take]);
    }

    // The checksum covers every entry of the set, including any benign
    // secondary entries past the name — a set whose checksum is computed over
    // the name entries alone rejects every volume that carries one.
    if checksum::entry_set(&bytes[..span]) != file.checksum { return Err(SetError::BadChecksum); }

    Ok(EntrySet { file, stream, units, offset, entries: count })
}

/// The entries of a set laid out, ready to be written.
///
/// The checksum is computed last and written into the file entry, which is why
/// nothing may edit these bytes afterwards without recomputing it.
/// # C: O(set entries)
pub fn build(attrs: u16, units: &[u16], hash: u16, start_cluster: u32, size: u64,
             valid_size: u64, flags: u8, create: Stamp, modify: Stamp, access: Stamp)
    -> Result<Vec<u8>, SetError> {
    let name_len = units.len();
    if name_len == 0 || name_len > MAX_NAME_LENGTH { return Err(SetError::BadCount); }
    let count = ES_IDX_FIRST_NAME + name::name_entries(name_len);
    let mut out = alloc::vec![0u8; count * DENTRY_BYTES];

    let file = FileEntry {
        num_ext: (count - 1) as u8,
        checksum: 0,
        attr: attrs,
        create,
        modify,
        access,
    };
    file::write(&file, &mut out[..DENTRY_BYTES]);

    let stream_entry = StreamEntry {
        flags,
        name_len: name_len as u8,
        name_hash: hash,
        valid_size,
        start_cluster,
        size,
    };
    let at = ES_IDX_STREAM * DENTRY_BYTES;
    stream::write(&stream_entry, &mut out[at..at + DENTRY_BYTES]);

    for (i, chunk) in units.chunks(NAME_CHARS_PER_ENTRY).enumerate() {
        let at = (ES_IDX_FIRST_NAME + i) * DENTRY_BYTES;
        stream::write_name(chunk, &mut out[at..at + DENTRY_BYTES]);
    }

    let sum = checksum::entry_set(&out);
    out[FILE_OFF_CHECKSUM..FILE_OFF_CHECKSUM + 2].copy_from_slice(&sum.to_le_bytes());
    Ok(out)
}

/// Recompute and store the checksum of a set already laid out.
///
/// Every path that changes any byte of a set ends here. A set written with a
/// stale checksum reads back as corrupt on every other implementation, and on
/// this one.
/// # C: O(set bytes)
pub fn reseal(bytes: &mut [u8]) {
    let sum = checksum::entry_set(bytes);
    bytes[FILE_OFF_CHECKSUM..FILE_OFF_CHECKSUM + 2].copy_from_slice(&sum.to_le_bytes());
}

/// Mark every entry of a set deleted, in place.
///
/// The type byte keeps its lower bits, so what the entry WAS stays readable —
/// which is what lets a recovery tool tell a deleted name from an unknown
/// entry type.
/// # C: O(set entries)
pub fn mark_deleted(bytes: &mut [u8]) {
    for entry in bytes.chunks_mut(DENTRY_BYTES) {
        entry[0] = super::kind::deleted_byte(entry[0]);
    }
}

/// The secondary entries of a set past its name, which a rewrite must carry
/// forward.
///
/// A benign secondary entry is one this implementation does not act on but may
/// not drop: an access-control entry or a vendor's own record. Rewriting a set
/// without them silently discards another system's data.
/// # C: O(set entries)
pub fn extra_entries(bytes: &[u8], name_len: usize) -> Vec<u8> {
    let first_extra = ES_IDX_FIRST_NAME + name::name_entries(name_len);
    let at = first_extra * DENTRY_BYTES;
    if bytes.len() <= at { return Vec::new(); }
    bytes[at..].to_vec()
}

/// Whether an entry of a set holds clusters a deletion must release.
/// # C: O(1)
pub fn secondary_allocation(entry: &[u8]) -> Option<(u32, u64)> {
    if entry.len() < DENTRY_BYTES { return None; }
    if !class_of(entry[0]).holds_allocation() { return None; }
    let flags = entry[SECONDARY_OFF_FLAGS];
    if flags & ALLOC_POSSIBLE == 0 { return None; }
    let start = u32::from_le_bytes([entry[SECONDARY_OFF_START_CLU],
                                    entry[SECONDARY_OFF_START_CLU + 1],
                                    entry[SECONDARY_OFF_START_CLU + 2],
                                    entry[SECONDARY_OFF_START_CLU + 3]]);
    let mut size = [0u8; 8];
    size.copy_from_slice(&entry[SECONDARY_OFF_SIZE..SECONDARY_OFF_SIZE + 8]);
    let size = u64::from_le_bytes(size);
    if start == 0 || size == 0 { return None; }
    Some((start, size))
}

/// Whether a run of entries is a set this implementation should present as a
/// name. # C: O(1)
pub fn is_name_set(ty: u8) -> bool { class_of(ty) == EntryKind::File }

#[cfg(test)]
#[path = "../tests/set.rs"]
mod tests;
