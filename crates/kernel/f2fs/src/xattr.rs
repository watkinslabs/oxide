//! Extended attributes: one list assembled from two places.
//!
//! An inode may carve a region out of its own address array for attributes and
//! may also own a whole separate block of them. The two are not two lists —
//! they are ONE list laid end to end, with the header at the start of the
//! inline part and entries running straight from the end of that part into the
//! start of the block. Searching them separately misses an entry that begins
//! in one and continues in the other.
//!
//! A name is not stored with its prefix. The prefix is an index byte, so
//! `user.foo` is stored as index one and the three bytes `foo`; a lookup that
//! compares the whole name never matches, and a listing that omits the prefix
//! returns names no caller can pass back.

use alloc::string::String;
use alloc::vec::Vec;

use crate::uapi::*;

/// One attribute.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Attr {
    pub index: u8,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Attr {
    /// The full name a caller sees, prefix included, or `None` for an index
    /// with no prefix this build exposes. # C: O(len)
    pub fn full_name(&self) -> Option<String> {
        let prefix = prefix_of(self.index)?;
        let mut s = String::from(prefix);
        s.push_str(&String::from_utf8_lossy(&self.name));
        Some(s)
    }
}

/// Why an attribute region could not be walked.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum XattrError {
    /// The region ends inside a record.
    Truncated,
    /// A record claims a length that would run past the region.
    BadLength,
}

/// The prefix an index byte stands for. # C: O(1)
pub fn prefix_of(index: u8) -> Option<&'static str> {
    match index {
        XATTR_INDEX_USER => Some("user."),
        XATTR_INDEX_POSIX_ACL_ACCESS => Some("system.posix_acl_access"),
        XATTR_INDEX_POSIX_ACL_DEFAULT => Some("system.posix_acl_default"),
        XATTR_INDEX_TRUSTED => Some("trusted."),
        XATTR_INDEX_SECURITY => Some("security."),
        XATTR_INDEX_ADVISE => Some("system.advise"),
        _ => None,
    }
}

/// Split a caller's name into the index it is stored under and the remainder.
/// # C: O(len)
pub fn split_name(full: &str) -> Option<(u8, &[u8])> {
    for index in [XATTR_INDEX_USER, XATTR_INDEX_TRUSTED, XATTR_INDEX_SECURITY] {
        let p = prefix_of(index)?;
        if let Some(rest) = full.strip_prefix(p) {
            if rest.is_empty() { return None; }
            return Some((index, rest.as_bytes()));
        }
    }
    // The two access-control names and the advice byte have no separator, so
    // they match whole rather than by prefix.
    for index in
        [XATTR_INDEX_POSIX_ACL_ACCESS, XATTR_INDEX_POSIX_ACL_DEFAULT, XATTR_INDEX_ADVISE]
    {
        if prefix_of(index)? == full { return Some((index, b"")); }
    }
    None
}

/// Bytes one record occupies, header, name and value together, rounded up.
/// # C: O(1)
pub fn entry_size(name_len: usize, value_size: usize) -> usize {
    xattr_align(XATTR_ENTRY_HEADER + name_len + value_size)
}

/// Whether the region begins with a header this format wrote.
///
/// A region never written to holds zeroes, which is not an error: it means the
/// inode has no attributes. That is reported as an empty list rather than as
/// corruption.
/// # C: O(1)
pub fn has_header(area: &[u8]) -> bool {
    le32(area, XATTR_H_MAGIC) == Some(XATTR_MAGIC)
}

/// Every attribute in the assembled region.
///
/// The list ends at the first record whose four header bytes are all zero,
/// which is the format's terminator rather than a length.
/// # C: O(region bytes)
pub fn list(area: &[u8]) -> Result<Vec<Attr>, XattrError> {
    if !has_header(area) { return Ok(Vec::new()); }
    let mut out = Vec::new();
    let mut at = XATTR_HEADER_SIZE;
    loop {
        let head = area.get(at..at + XATTR_ENTRY_HEADER).ok_or(XattrError::Truncated)?;
        if head == [0u8; XATTR_ENTRY_HEADER] { break; }
        let index = head[XATTR_E_NAME_INDEX];
        let name_len = head[XATTR_E_NAME_LEN] as usize;
        let value_size = u16::from_le_bytes([head[XATTR_E_VALUE_SIZE], head[XATTR_E_VALUE_SIZE + 1]])
            as usize;
        let body = at + XATTR_ENTRY_HEADER;
        let end = at + entry_size(name_len, value_size);
        if end > area.len() || end <= at { return Err(XattrError::BadLength); }
        let name = area.get(body..body + name_len).ok_or(XattrError::Truncated)?;
        let value = area
            .get(body + name_len..body + name_len + value_size)
            .ok_or(XattrError::Truncated)?;
        out.push(Attr { index, name: name.to_vec(), value: value.to_vec() });
        at = end;
    }
    Ok(out)
}

/// The value stored under one index and name. # C: O(region bytes)
pub fn get(area: &[u8], index: u8, name: &[u8]) -> Result<Option<Vec<u8>>, XattrError> {
    Ok(list(area)?.into_iter().find(|a| a.index == index && a.name == name).map(|a| a.value))
}

/// The names a listing reports, each terminated the way the interface wants.
/// # C: O(region bytes)
pub fn names(area: &[u8]) -> Result<Vec<u8>, XattrError> {
    let mut out = Vec::new();
    for a in list(area)? {
        let Some(full) = a.full_name() else { continue };
        out.extend_from_slice(full.as_bytes());
        out.push(0);
    }
    Ok(out)
}

/// Join an inode's inline region and its attribute block into one list.
///
/// The block contributes only the bytes ahead of its node footer: the footer
/// is not part of the attribute region and reading it as records produces one
/// with an enormous length.
/// # C: O(region bytes)
pub fn joined(inline: &[u8], block: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(inline.len() + VALID_XATTR_BLOCK_SIZE + 4);
    out.extend_from_slice(inline);
    if let Some(b) = block {
        let take = b.len().min(VALID_XATTR_BLOCK_SIZE);
        out.extend_from_slice(&b[..take]);
    }
    // The padding word is what makes the terminator readable when the last
    // record ends exactly at the region's end.
    out.extend_from_slice(&[0u8; 4]);
    out
}

#[cfg(test)]
#[path = "tests/xattr.rs"]
mod tests;
