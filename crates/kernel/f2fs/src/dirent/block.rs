//! Reading entries out of one dentry area.
//!
//! The walk advances by the SLOT COUNT the entry's name needs, never by one.
//! A nine-byte name occupies two slots, and the record belonging to the second
//! slot holds none of it — advancing one slot at a time reads that record's
//! eleven arbitrary bytes as a hash, an inode number and a length, which is
//! how a directory grows entries nobody created.

use alloc::string::String;
use alloc::vec::Vec;

use crate::uapi::*;

use super::layout::{is_used, Layout};

/// One directory entry, resolved.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    pub hash: u32,
    pub ino: u32,
    pub file_type: u8,
    pub name: Vec<u8>,
    /// Which slot the entry starts at, so a writer can find it again.
    pub slot: usize,
}

impl Entry {
    /// The name as text, with invalid sequences replaced.
    ///
    /// A name is bytes on the medium and this filesystem imposes nothing on
    /// them, so a name no encoder should have produced is shown rather than
    /// making its directory unreadable.
    /// # C: O(len)
    pub fn name_str(&self) -> String { String::from_utf8_lossy(&self.name).into_owned() }
}

/// Why an area could not be walked.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DirError {
    /// The area is shorter than its own layout needs.
    Truncated,
    /// An entry names a length longer than the format allows, or one whose
    /// slots run past the end of the area.
    BadNameLen { slot: usize, len: usize },
}

/// Every live entry of `area`, in slot order.
///
/// An entry with a zero length is skipped by one slot rather than trusted: the
/// format leaves such records behind and advancing by zero slots would not
/// terminate.
/// # C: O(area entries)
pub fn entries(area: &[u8], l: &Layout) -> Result<Vec<Entry>, DirError> {
    let mut out = Vec::new();
    walk(area, l, |e| { out.push(e); true })?;
    Ok(out)
}

/// The entry whose hash and name both match, if the area holds one.
///
/// The hash is compared first because it is four bytes against a name of up to
/// two hundred and fifty-five; the name comparison is what actually decides,
/// since two names may share a hash.
/// # C: O(area entries)
pub fn find(area: &[u8], l: &Layout, hash: u32, name: &[u8]) -> Result<Option<Entry>, DirError> {
    let mut hit = None;
    walk(area, l, |e| {
        if e.hash == hash && e.name == name { hit = Some(e); false } else { true }
    })?;
    Ok(hit)
}

/// The entry a caller's own predicate accepts.
///
/// A folding directory cannot use [`find`]: the hash it searches by is over
/// the FOLDED name and the comparison is a fold-equality, neither of which is
/// a byte comparison against the stored bytes.
/// # C: O(area entries)
pub fn find_with<F>(area: &[u8], l: &Layout, mut accept: F) -> Result<Option<Entry>, DirError>
where
    F: FnMut(u32, &[u8]) -> bool,
{
    let mut hit = None;
    walk(area, l, |e| {
        if accept(e.hash, &e.name) { hit = Some(e); false } else { true }
    })?;
    Ok(hit)
}

/// Walk `area`, handing each live entry to `f` until it returns false.
/// # C: O(area entries)
pub fn walk<F: FnMut(Entry) -> bool>(area: &[u8], l: &Layout, mut f: F)
    -> Result<(), DirError> {
    if !l.fits() || area.len() < l.len { return Err(DirError::Truncated); }
    let mut slot = 0usize;
    while slot < l.max {
        if !is_used(area, slot) { slot += 1; continue; }
        let at = l.dentry_off(slot);
        let name_len = le16(area, at + DE_NAME_LEN).ok_or(DirError::Truncated)? as usize;
        if name_len == 0 { slot += 1; continue; }
        let slots = dentry_slots(name_len);
        if name_len > NAME_LEN || slot + slots > l.max {
            return Err(DirError::BadNameLen { slot, len: name_len });
        }
        let name_at = l.name_off(slot);
        let name = area.get(name_at..name_at + name_len).ok_or(DirError::Truncated)?;
        let entry = Entry {
            hash: le32(area, at + DE_HASH_CODE).ok_or(DirError::Truncated)?,
            ino: le32(area, at + DE_INO).ok_or(DirError::Truncated)?,
            file_type: *area.get(at + DE_FILE_TYPE).ok_or(DirError::Truncated)?,
            name: name.to_vec(),
            slot,
        };
        if !f(entry) { return Ok(()); }
        slot += slots;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/dirent_block.rs"]
mod tests;
