//! Putting an entry into a directory's index.
//!
//! The tree is ordered by the volume's own up-case table, so an entry appended
//! rather than placed in order produces a node a descent cannot search: the
//! entries after it sort before it, and a lookup that reaches one of them
//! stops.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib;
use crate::index::{self, entry};
use crate::name::FileName;
use crate::record::Reference;
use crate::uapi::*;

use super::{edit, Volume};

/// The `$INDEX_ROOT` a new directory starts with: a tree of one empty node.
/// # C: O(1)
pub fn empty_index_root(block_size: u32, cluster_size: u32) -> Vec<u8> {
    let mut out = alloc::vec![0u8; IROOT_OFF_IHDR + SIZEOF_IHDR + SIZEOF_DE];
    out[IROOT_OFF_TYPE..IROOT_OFF_TYPE + 4].copy_from_slice(&ATTR_NAME.to_le_bytes());
    out[IROOT_OFF_RULE..IROOT_OFF_RULE + 4].copy_from_slice(&COLLATION_FILENAME.to_le_bytes());
    out[IROOT_OFF_BLOCK_SIZE..IROOT_OFF_BLOCK_SIZE + 4].copy_from_slice(&block_size.to_le_bytes());
    // The field counts CLUSTERS when a block is at least one, and sectors
    // otherwise — the same shape as the boot sector's own size fields.
    out[IROOT_OFF_BLOCK_CLST] = if block_size >= cluster_size {
        (block_size / cluster_size) as u8
    } else {
        (block_size >> SECTOR_SHIFT) as u8
    };
    let at = IROOT_OFF_IHDR;
    let de_off = SIZEOF_IHDR as u32;
    out[at + IHDR_OFF_DE_OFF..at + IHDR_OFF_DE_OFF + 4].copy_from_slice(&de_off.to_le_bytes());
    let used = de_off + SIZEOF_DE as u32;
    out[at + IHDR_OFF_USED..at + IHDR_OFF_USED + 4].copy_from_slice(&used.to_le_bytes());
    out[at + IHDR_OFF_TOTAL..at + IHDR_OFF_TOTAL + 4].copy_from_slice(&used.to_le_bytes());
    let e = at + de_off as usize;
    out[e + DE_OFF_SIZE..e + DE_OFF_SIZE + 2].copy_from_slice(&(SIZEOF_DE as u16).to_le_bytes());
    out[e + DE_OFF_FLAGS..e + DE_OFF_FLAGS + 2].copy_from_slice(&NTFS_IE_LAST.to_le_bytes());
    out
}

/// Rebuild a node's bytes from an ordered list of entries.
///
/// The end entry is kept LAST whatever the list's order says, because it is
/// what tells a reader the node is finished rather than a key that sorts
/// after everything.
/// # C: O(entries)
pub fn rebuild_node(entries: &[Vec<u8>], last: &[u8], header_at: usize, total: u32,
                    flags: u32) -> Option<Vec<u8>> {
    let de_off = SIZEOF_IHDR as u32;
    let mut body = Vec::new();
    for e in entries { body.extend_from_slice(e); }
    body.extend_from_slice(last);
    let used = de_off + body.len() as u32;
    if used > total { return None; }
    let mut out = alloc::vec![0u8; SIZEOF_IHDR + body.len()];
    out[IHDR_OFF_DE_OFF..IHDR_OFF_DE_OFF + 4].copy_from_slice(&de_off.to_le_bytes());
    out[IHDR_OFF_USED..IHDR_OFF_USED + 4].copy_from_slice(&used.to_le_bytes());
    out[IHDR_OFF_TOTAL..IHDR_OFF_TOTAL + 4].copy_from_slice(&total.to_le_bytes());
    out[IHDR_OFF_FLAGS..IHDR_OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
    out[SIZEOF_IHDR..].copy_from_slice(&body);
    let _ = header_at;
    Some(out)
}

impl<S: SectorSource> Volume<S> {
    /// Put an entry naming `reference` into `parent`'s index.
    /// # C: O(index bytes)
    pub(crate) fn index_insert(&mut self, parent: u64, reference: &Reference, fname: &FileName)
        -> Result<(), Errno> {
        let key = crate::name::write_filename(fname);
        let new_entry = entry::build(reference, &key, None);
        let (bytes, attrs) = self.read_live_record(parent)?;
        let root_attr = attrib::find(&attrs, ATTR_ROOT, &I30_NAME).cloned().ok_or(Errno::Enotdir)?;
        let root_data = self.attribute_bytes(&bytes, &attrs, &root_attr)?;
        let root = index::parse_root(&root_data).ok_or(Errno::Eio)?;

        // A tree with child nodes needs the entry placed in the leaf its key
        // belongs to, and a leaf with no room needs the node split. Splitting
        // is not done here, so a tree that has grown past its root is refused
        // rather than corrupted.
        if root.header.has_subnodes() { return Err(Errno::Enospc); }

        let existing = entry::entries(&root_data, root.header_at, &root.header, root.indexed_type);
        let position = index::walk::insert_position(&existing, &fname.units, &self.upcase);
        let mut ordered: Vec<Vec<u8>> = Vec::new();
        let mut last: Vec<u8> = entry::build_last(None);
        for (i, e) in existing.iter().enumerate() {
            if i == position { ordered.push(new_entry.clone()); }
            let span = &root_data[e.offset..e.offset + usize::from(e.size)];
            if e.is_last() { last = span.to_vec(); } else { ordered.push(span.to_vec()); }
        }
        if position >= existing.len() { ordered.push(new_entry); }

        // The root is resident, so its size is bounded by the record rather
        // than by a block: whatever fits is the tree's whole capacity here.
        let head = &root_data[..IROOT_OFF_IHDR];
        let body_total = ordered.iter().map(|e| e.len()).sum::<usize>() + last.len()
            + SIZEOF_IHDR;
        let node = rebuild_node(&ordered, &last, root.header_at, body_total as u32,
                                root.header.flags).ok_or(Errno::Enospc)?;
        let mut data = Vec::with_capacity(head.len() + node.len());
        data.extend_from_slice(head);
        data.extend_from_slice(&node);
        self.replace_index_root(parent, &data)
    }

    /// Write a directory's `$INDEX_ROOT` back. # C: O(record bytes)
    pub(crate) fn replace_index_root(&mut self, parent: u64, data: &[u8]) -> Result<(), Errno> {
        let (mut bytes, header) = self.read_record_raw(parent)?;
        let attrs = attrib::parse_all(&bytes, &header);
        let root_attr = attrib::find(&attrs, ATTR_ROOT, &I30_NAME).ok_or(Errno::Enotdir)?;
        let at = root_attr.offset;
        let id = root_attr.id;
        let attr = edit::resident(ATTR_ROOT, &I30_NAME, id, false, data);
        edit::replace_at(&mut bytes, &header, at, &attr)?;
        self.write_record(parent, &mut bytes)
    }
}
