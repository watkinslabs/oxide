//! The file entry: the first of a set, and the only one that knows how many
//! follow it.

use crate::time::Stamp;
use crate::uapi::*;

/// The first entry of a set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileEntry {
    /// Entries that FOLLOW this one in the set.
    pub num_ext: u8,
    /// The set's checksum, as recorded.
    pub checksum: u16,
    pub attr: u16,
    pub create: Stamp,
    pub modify: Stamp,
    pub access: Stamp,
}

impl FileEntry {
    /// Whether this set names a directory. # C: O(1)
    pub fn is_dir(&self) -> bool { self.attr & ATTR_SUBDIR != 0 }

    /// Whether this set names the volume rather than a file. # C: O(1)
    pub fn is_volume(&self) -> bool { self.attr & ATTR_VOLUME != 0 }

    /// Whether the entry refuses writes. # C: O(1)
    pub fn is_readonly(&self) -> bool { self.attr & ATTR_READONLY != 0 }

    /// Entries in the whole set, this one included. # C: O(1)
    pub fn set_len(&self) -> usize { self.num_ext as usize + 1 }
}

/// Read one 16-bit field. # C: O(1)
fn le16(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }

/// Decode a file entry from its 32 bytes.
///
/// `None` when the bytes are not a file entry; the caller has already
/// classified the type byte, so this is a length and type guard rather than a
/// second classification.
/// # C: O(1)
pub fn parse(bytes: &[u8]) -> Option<FileEntry> {
    if bytes.len() < DENTRY_BYTES || bytes[0] != TYPE_FILE { return None; }
    Some(FileEntry {
        num_ext: bytes[FILE_OFF_NUM_EXT],
        checksum: le16(bytes, FILE_OFF_CHECKSUM),
        attr: le16(bytes, FILE_OFF_ATTR),
        create: Stamp {
            fields: dostime::DosTime {
                time: le16(bytes, FILE_OFF_CREATE_TIME),
                date: le16(bytes, FILE_OFF_CREATE_DATE),
                cs: bytes[FILE_OFF_CREATE_CS],
            },
            tz: bytes[FILE_OFF_CREATE_TZ],
        },
        modify: Stamp {
            fields: dostime::DosTime {
                time: le16(bytes, FILE_OFF_MODIFY_TIME),
                date: le16(bytes, FILE_OFF_MODIFY_DATE),
                cs: bytes[FILE_OFF_MODIFY_CS],
            },
            tz: bytes[FILE_OFF_MODIFY_TZ],
        },
        // The access timestamp has no centisecond byte of its own, so its
        // granularity is two seconds where the other two are ten
        // milliseconds.
        access: Stamp {
            fields: dostime::DosTime {
                time: le16(bytes, FILE_OFF_ACCESS_TIME),
                date: le16(bytes, FILE_OFF_ACCESS_DATE),
                cs: 0,
            },
            tz: bytes[FILE_OFF_ACCESS_TZ],
        },
    })
}

/// Lay a file entry out into its 32 bytes.
///
/// The checksum field is written as recorded, which for a set being built is
/// zero: the set's checksum covers these bytes and cannot be computed until
/// every entry beside them is laid out.
/// # C: O(1)
pub fn write(entry: &FileEntry, out: &mut [u8]) {
    out[..DENTRY_BYTES].fill(0);
    out[0] = TYPE_FILE;
    out[FILE_OFF_NUM_EXT] = entry.num_ext;
    out[FILE_OFF_CHECKSUM..FILE_OFF_CHECKSUM + 2].copy_from_slice(&entry.checksum.to_le_bytes());
    out[FILE_OFF_ATTR..FILE_OFF_ATTR + 2].copy_from_slice(&entry.attr.to_le_bytes());
    out[FILE_OFF_CREATE_TIME..FILE_OFF_CREATE_TIME + 2]
        .copy_from_slice(&entry.create.fields.time.to_le_bytes());
    out[FILE_OFF_CREATE_DATE..FILE_OFF_CREATE_DATE + 2]
        .copy_from_slice(&entry.create.fields.date.to_le_bytes());
    out[FILE_OFF_MODIFY_TIME..FILE_OFF_MODIFY_TIME + 2]
        .copy_from_slice(&entry.modify.fields.time.to_le_bytes());
    out[FILE_OFF_MODIFY_DATE..FILE_OFF_MODIFY_DATE + 2]
        .copy_from_slice(&entry.modify.fields.date.to_le_bytes());
    out[FILE_OFF_ACCESS_TIME..FILE_OFF_ACCESS_TIME + 2]
        .copy_from_slice(&entry.access.fields.time.to_le_bytes());
    out[FILE_OFF_ACCESS_DATE..FILE_OFF_ACCESS_DATE + 2]
        .copy_from_slice(&entry.access.fields.date.to_le_bytes());
    out[FILE_OFF_CREATE_CS] = entry.create.fields.cs;
    out[FILE_OFF_MODIFY_CS] = entry.modify.fields.cs;
    out[FILE_OFF_CREATE_TZ] = entry.create.tz;
    out[FILE_OFF_MODIFY_TZ] = entry.modify.tz;
    out[FILE_OFF_ACCESS_TZ] = entry.access.tz;
}

/// The attribute word a newly created entry carries.
///
/// A directory is marked as one; a file is marked archive, which is what says
/// "changed since the last backup" and is what every implementation sets on
/// creation.
/// # C: O(1)
pub fn new_attrs(is_dir: bool) -> u16 { if is_dir { ATTR_SUBDIR } else { ATTR_ARCHIVE } }
