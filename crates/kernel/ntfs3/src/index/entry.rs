//! One index entry, and the filename key it carries.
//!
//! The child pointer is the trap. It is not a field of the entry: it is the
//! LAST eight bytes of whatever length the entry declares, present only when
//! the entry says it has a child. Reading it at a fixed offset gives a key's
//! characters as a block number.

use alloc::vec::Vec;

use crate::name::FileName;
use crate::uapi::*;

/// What an entry is keyed on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Key {
    /// A directory's entries are keyed on a filename record.
    Name(FileName),
    /// Anything else: the key's raw bytes, for an index this implementation
    /// does not interpret.
    Raw(Vec<u8>),
}

/// One entry of an index node.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IndexEntry {
    /// The record this entry names.
    pub reference: crate::record::Reference,
    /// Bytes the entry occupies.
    pub size: u16,
    pub key_size: u16,
    pub flags: u16,
    /// The child node's block number, when the entry has one.
    pub child: Option<u64>,
    pub key: Option<Key>,
    /// Where the entry sits within its node's bytes.
    pub offset: usize,
}

impl IndexEntry {
    /// Whether this is the end entry, which no key belongs to. # C: O(1)
    pub fn is_last(&self) -> bool { self.flags & NTFS_IE_LAST != 0 }

    /// Whether this entry has a child node. # C: O(1)
    pub fn has_child(&self) -> bool { self.flags & NTFS_IE_HAS_SUBNODES != 0 }

    /// The filename this entry names, when it names one. # C: O(1)
    pub fn name(&self) -> Option<&FileName> {
        match &self.key { Some(Key::Name(f)) => Some(f), _ => None }
    }
}

/// Read one 16-bit field. # C: O(1)
fn le16(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }

/// Decode the entry at `at`, whose key is of `indexed_type`. # C: O(key bytes)
pub fn parse(bytes: &[u8], at: usize, indexed_type: u32) -> Option<IndexEntry> {
    if at + SIZEOF_DE > bytes.len() { return None; }
    let size = le16(bytes, at + DE_OFF_SIZE);
    if usize::from(size) < SIZEOF_DE { return None; }
    let end = at.checked_add(usize::from(size))?;
    if end > bytes.len() { return None; }
    let key_size = le16(bytes, at + DE_OFF_KEY_SIZE);
    let flags = le16(bytes, at + DE_OFF_FLAGS);

    // The child pointer occupies the entry's last eight bytes, so the key can
    // only reach that far minus eight.
    let child = if flags & NTFS_IE_HAS_SUBNODES != 0 {
        if usize::from(size) < SIZEOF_DE + 8 { return None; }
        let vbn_at = end - 8;
        let mut vbn = [0u8; 8];
        vbn.copy_from_slice(&bytes[vbn_at..vbn_at + 8]);
        Some(u64::from_le_bytes(vbn))
    } else {
        None
    };

    let key = if flags & NTFS_IE_LAST != 0 || key_size == 0 {
        None
    } else {
        let start = at + SIZEOF_DE;
        let stop = start.checked_add(usize::from(key_size))?;
        let limit = if child.is_some() { end - 8 } else { end };
        if stop > limit { return None; }
        let raw = &bytes[start..stop];
        if indexed_type == ATTR_NAME {
            Some(Key::Name(crate::name::parse_filename(raw)?))
        } else {
            Some(Key::Raw(raw.to_vec()))
        }
    };

    Some(IndexEntry {
        reference: crate::record::reference(bytes, at + DE_OFF_REF),
        size,
        key_size,
        flags,
        child,
        key,
        offset: at,
    })
}

/// Every entry of one node, in order.
///
/// The walk stops at the end entry — which is present in every node and is
/// what says the node is finished — and at the node's used length, whichever
/// comes first.
/// # C: O(node bytes)
pub fn entries(bytes: &[u8], header_at: usize, header: &super::NodeHeader, indexed_type: u32)
    -> Vec<IndexEntry> {
    let mut out = Vec::new();
    let limit = header_at + header.used as usize;
    let mut at = header_at + header.de_off as usize;
    while at + SIZEOF_DE <= limit {
        let Some(entry) = parse(bytes, at, indexed_type) else { break };
        let size = usize::from(entry.size);
        let last = entry.is_last();
        out.push(entry);
        if last { break; }
        at += size;
    }
    out
}

/// Build an entry naming `reference` with `key` bytes. # C: O(key bytes)
pub fn build(reference: &crate::record::Reference, key: &[u8], child: Option<u64>) -> Vec<u8> {
    let base = SIZEOF_DE + key.len();
    let size = (base + if child.is_some() { 8 } else { 0 }).next_multiple_of(8);
    let mut out = alloc::vec![0u8; size];
    crate::record::write_reference(&mut out, DE_OFF_REF, reference);
    out[DE_OFF_SIZE..DE_OFF_SIZE + 2].copy_from_slice(&(size as u16).to_le_bytes());
    out[DE_OFF_KEY_SIZE..DE_OFF_KEY_SIZE + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    let flags = if child.is_some() { NTFS_IE_HAS_SUBNODES } else { 0 };
    out[DE_OFF_FLAGS..DE_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
    out[SIZEOF_DE..SIZEOF_DE + key.len()].copy_from_slice(key);
    if let Some(vbn) = child {
        let at = size - 8;
        out[at..at + 8].copy_from_slice(&vbn.to_le_bytes());
    }
    out
}

/// Build the end entry every node finishes with. # C: O(1)
pub fn build_last(child: Option<u64>) -> Vec<u8> {
    let size = (SIZEOF_DE + if child.is_some() { 8 } else { 0 }).next_multiple_of(8);
    let mut out = alloc::vec![0u8; size];
    out[DE_OFF_SIZE..DE_OFF_SIZE + 2].copy_from_slice(&(size as u16).to_le_bytes());
    let flags = NTFS_IE_LAST | if child.is_some() { NTFS_IE_HAS_SUBNODES } else { 0 };
    out[DE_OFF_FLAGS..DE_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
    if let Some(vbn) = child {
        let at = size - 8;
        out[at..at + 8].copy_from_slice(&vbn.to_le_bytes());
    }
    out
}
