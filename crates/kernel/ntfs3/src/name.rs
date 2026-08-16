//! Names: the `$FILE_NAME` attribute, and the four namespaces one file's name
//! can be recorded in.
//!
//! A file usually has TWO name records in its parent's index: a long one and
//! an 8.3 alias, and both point at the same record. Listing both shows every
//! file twice; listing neither hides files whose only name is an alias. The
//! rule is to prefer the long name and suppress the DOS alias when a long one
//! exists — which is what the reference does and what every tool expects.
//!
//! Comparison is through the volume's own `$UpCase` table, not a rule of the
//! format, so the same two names collide here and on the system that wrote
//! the medium.

use alloc::string::String;
use alloc::vec::Vec;

use crate::record::Reference;
use crate::uapi::*;

/// A `$FILE_NAME` record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileName {
    /// The directory holding this name.
    pub parent: Reference,
    pub create_time: i64,
    pub modify_time: i64,
    pub change_time: i64,
    pub access_time: i64,
    pub alloc_size: u64,
    pub data_size: u64,
    pub attributes: u32,
    pub namespace: u8,
    pub units: Vec<u16>,
}

impl FileName {
    /// The name as a string. # C: O(name length)
    pub fn name(&self) -> String { decode(&self.units) }

    /// Whether this record is the 8.3 alias rather than the real name.
    /// # C: O(1)
    pub fn is_dos_alias(&self) -> bool { self.namespace == FILE_NAME_DOS }

    /// Whether this record names a directory. # C: O(1)
    pub fn is_dir(&self) -> bool { self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 }
}

/// Read one 16-bit field. # C: O(1)
fn le16(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }

/// Read one 32-bit field. # C: O(1)
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Read one 64-bit field. # C: O(1)
fn le64(bytes: &[u8], at: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(out)
}

/// Decode a `$FILE_NAME` record. # C: O(name length)
pub fn parse_filename(bytes: &[u8]) -> Option<FileName> {
    if bytes.len() < SIZEOF_FILENAME_MIN { return None; }
    let name_len = usize::from(bytes[FN_OFF_NAME_LEN]);
    if name_len > NTFS_NAME_LEN { return None; }
    let stop = FN_OFF_NAME.checked_add(name_len * 2)?;
    if stop > bytes.len() { return None; }
    let mut units = Vec::with_capacity(name_len);
    for i in 0..name_len { units.push(le16(bytes, FN_OFF_NAME + i * 2)); }
    Some(FileName {
        parent: crate::record::reference(bytes, FN_OFF_HOME),
        create_time: le64(bytes, FN_OFF_CR_TIME) as i64,
        modify_time: le64(bytes, FN_OFF_M_TIME) as i64,
        change_time: le64(bytes, FN_OFF_C_TIME) as i64,
        access_time: le64(bytes, FN_OFF_A_TIME) as i64,
        alloc_size: le64(bytes, FN_OFF_ALLOC_SIZE),
        data_size: le64(bytes, FN_OFF_DATA_SIZE),
        attributes: le32(bytes, FN_OFF_FA),
        namespace: bytes[FN_OFF_TYPE],
        units,
    })
}

/// Lay a `$FILE_NAME` record out. # C: O(name length)
pub fn write_filename(fname: &FileName) -> Vec<u8> {
    let mut out = alloc::vec![0u8; FN_OFF_NAME + fname.units.len() * 2];
    crate::record::write_reference(&mut out, FN_OFF_HOME, &fname.parent);
    out[FN_OFF_CR_TIME..FN_OFF_CR_TIME + 8]
        .copy_from_slice(&(fname.create_time as u64).to_le_bytes());
    out[FN_OFF_M_TIME..FN_OFF_M_TIME + 8]
        .copy_from_slice(&(fname.modify_time as u64).to_le_bytes());
    out[FN_OFF_C_TIME..FN_OFF_C_TIME + 8]
        .copy_from_slice(&(fname.change_time as u64).to_le_bytes());
    out[FN_OFF_A_TIME..FN_OFF_A_TIME + 8]
        .copy_from_slice(&(fname.access_time as u64).to_le_bytes());
    out[FN_OFF_ALLOC_SIZE..FN_OFF_ALLOC_SIZE + 8].copy_from_slice(&fname.alloc_size.to_le_bytes());
    out[FN_OFF_DATA_SIZE..FN_OFF_DATA_SIZE + 8].copy_from_slice(&fname.data_size.to_le_bytes());
    out[FN_OFF_FA..FN_OFF_FA + 4].copy_from_slice(&fname.attributes.to_le_bytes());
    out[FN_OFF_NAME_LEN] = fname.units.len() as u8;
    out[FN_OFF_TYPE] = fname.namespace;
    for (i, unit) in fname.units.iter().enumerate() {
        let at = FN_OFF_NAME + i * 2;
        out[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Decode UTF-16 units into a string.
///
/// An unpaired surrogate is replaced rather than refused: a medium another
/// system wrote can carry one, and refusing makes the whole directory
/// unreadable instead of one name odd-looking.
/// # C: O(units.len())
pub fn decode(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Encode a name for this filesystem. # C: O(name bytes)
pub fn encode(name: &str) -> Option<Vec<u16>> {
    let units: Vec<u16> = name.encode_utf16().collect();
    if units.is_empty() || units.len() > NTFS_NAME_LEN { return None; }
    Some(units)
}

/// The namespace paired with `ty`, which a file's other name record uses.
/// # C: O(1)
pub fn paired_namespace(ty: u8) -> u8 {
    match ty {
        FILE_NAME_UNICODE => FILE_NAME_DOS,
        FILE_NAME_DOS => FILE_NAME_UNICODE,
        _ => FILE_NAME_POSIX,
    }
}

/// Which of a record's several name records to present.
///
/// A name in the combined namespace is both the long name and the alias, so it
/// is preferred outright; otherwise the long name wins and the alias is only
/// used when there is nothing else. Presenting the alias beside the long name
/// shows one file twice.
/// # C: O(names)
pub fn preferred(names: &[FileName]) -> Option<&FileName> {
    names.iter().find(|n| n.namespace == FILE_NAME_UNICODE_AND_DOS)
        .or_else(|| names.iter().find(|n| n.namespace == FILE_NAME_POSIX))
        .or_else(|| names.iter().find(|n| n.namespace == FILE_NAME_UNICODE))
        .or_else(|| names.first())
}

/// Whether a name record should be LISTED, given the other names its record
/// carries.
///
/// The DOS alias is suppressed exactly when a long name exists: it names the
/// same file, and a listing carrying both shows the file twice.
/// # C: O(1)
pub fn should_list(name: &FileName, has_long_name: bool) -> bool {
    !(name.namespace == FILE_NAME_DOS && has_long_name)
}

#[cfg(test)]
#[path = "tests/name.rs"]
mod tests;
