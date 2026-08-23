//! Putting an entry into a directory's index.
//!
//! The tree is ordered by the volume's own up-case table, so an entry appended
//! rather than placed in order produces a node a descent cannot search: the
//! entries after it sort before it, and a lookup that reaches one of them
//! stops.

use alloc::vec;
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
    rebuild_node_at(entries, last, SIZEOF_IHDR as u32, total, flags, header_at)
}

fn rebuild_node_at(entries: &[Vec<u8>], last: &[u8], de_off: u32, total: u32, flags: u32,
                   _header_at: usize) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    for e in entries { body.extend_from_slice(e); }
    body.extend_from_slice(last);
    let used = de_off + body.len() as u32;
    if used > total { return None; }
    let mut out = alloc::vec![0u8; de_off as usize + body.len()];
    out[IHDR_OFF_DE_OFF..IHDR_OFF_DE_OFF + 4].copy_from_slice(&de_off.to_le_bytes());
    out[IHDR_OFF_USED..IHDR_OFF_USED + 4].copy_from_slice(&used.to_le_bytes());
    out[IHDR_OFF_TOTAL..IHDR_OFF_TOTAL + 4].copy_from_slice(&total.to_le_bytes());
    out[IHDR_OFF_FLAGS..IHDR_OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
    out[de_off as usize..].copy_from_slice(&body);
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
        let record_header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
        let root_attr = attrib::find(&attrs, ATTR_ROOT, &I30_NAME).cloned().ok_or(Errno::Enotdir)?;
        let root_data = self.attribute_bytes(&bytes, &attrs, &root_attr)?;
        let root = index::parse_root(&root_data).ok_or(Errno::Eio)?;

        if root.header.has_subnodes() {
            return self.index_insert_allocation(parent, &new_entry, fname, &root);
        }

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
        let candidate = rebuild_node(&ordered, &last, root.header_at, body_total as u32,
                                     root.header.flags).ok_or(Errno::Enospc)?;
        let mut candidate_data = Vec::with_capacity(head.len() + candidate.len());
        candidate_data.extend_from_slice(head);
        candidate_data.extend_from_slice(&candidate);
        let candidate_attr = edit::resident(ATTR_ROOT, &I30_NAME, root_attr.id, false,
                                             &candidate_data);
        let root_fits = candidate_attr.len() <= edit::free_space(&bytes, &record_header)
            + root_attr.size as usize;
        if root_fits {
            return self.replace_index_root(parent, &candidate_data);
        }

        // Linux changes a full resident root into a one-child root. The old
        // entries remain in sorted order in allocation block zero; subsequent
        // inserts operate on that block and may split it into more blocks.
        let block = self.index_block_from_entries(&ordered, &last, root.block_size, 0)?;
        let child = entry::build_last(Some(0));
        let root_node = rebuild_node(&[], &child, root.header_at,
                                     (SIZEOF_IHDR + child.len()) as u32,
                                     INDEX_HDR_HAS_SUBNODES).ok_or(Errno::Eio)?;
        let mut data = Vec::with_capacity(head.len() + root_node.len());
        data.extend_from_slice(head);
        data.extend_from_slice(&root_node);
        self.install_index_allocation(parent, &data, root.block_size, &block)
    }

    /// Insert into the first allocation node. Its fixed size is deliberately
    /// enforced before any bytes are published; a full node is split by the
    /// next growth step rather than producing an unreadable overrun.
    fn index_insert_allocation(&mut self, parent: u64, new_entry: &[u8], fname: &FileName,
                               root: &index::Root) -> Result<(), Errno> {
        let idx = self.open_index(parent)?;
        let alloc = idx.alloc.as_ref().ok_or(Errno::Eio)?;
        let (alloc_bytes, attrs) = (&idx.bytes, &idx.attrs);
        let runs = self.attribute_runs(alloc_bytes, attrs, alloc)?;
        let mut block = vec![0u8; root.block_size as usize];
        let got = self.read_attribute(alloc_bytes, attrs, alloc, 0, &mut block)?;
        if got != block.len() { return Err(Errno::Eio); }
        crate::fixup::post_read(&mut block, false).map_err(|e| e.errno())?;
        let (header, _) = index::parse_block(&block, 0).ok_or(Errno::Eio)?;
        let existing = entry::entries(&block, IB_OFF_IHDR, &header, root.indexed_type);
        let position = index::walk::insert_position(&existing, &fname.units, &self.upcase);
        let mut ordered = Vec::new();
        let mut last = entry::build_last(None);
        for (i, e) in existing.iter().enumerate() {
            if i == position { ordered.push(new_entry.to_vec()); }
            let span = &block[e.offset..e.offset + usize::from(e.size)];
            if e.is_last() { last = span.to_vec(); } else { ordered.push(span.to_vec()); }
        }
        if position >= existing.len() { ordered.push(new_entry.to_vec()); }
        let rebuilt = self.index_block_from_entries(&ordered, &last, root.block_size, 0)?;
        self.write_runs(&runs, 0, &rebuilt)
    }

    fn index_block_from_entries(&self, entries: &[Vec<u8>], last: &[u8], size: u32, vbn: u64)
        -> Result<Vec<u8>, Errno> {
        let mut block = index::format_block(size, vbn);
        let at = IB_OFF_IHDR;
        let de_off = u32::from_le_bytes(block[at + IHDR_OFF_DE_OFF..at + IHDR_OFF_DE_OFF + 4]
                                        .try_into().map_err(|_| Errno::Eio)?);
        let node = rebuild_node_at(entries, last, de_off, size - at as u32, 0, at)
            .ok_or(Errno::Enospc)?;
        block[at..at + node.len()].copy_from_slice(&node);
        crate::fixup::pre_write(&mut block, 1).map_err(|e| e.errno())?;
        Ok(block)
    }

    fn install_index_allocation(&mut self, parent: u64, root_data: &[u8], block_size: u32,
                                block: &[u8]) -> Result<(), Errno> {
        let clusters = self.geo.clusters_for(u64::from(block_size));
        let runs = self.alloc_clusters(clusters)?;
        let bitmap = [1u8];
        let result = (|| {
            let (mut bytes, header) = self.read_record_raw(parent)?;
            let attrs = attrib::parse_all(&bytes, &header);
            let root_attr = attrib::find(&attrs, ATTR_ROOT, &I30_NAME).ok_or(Errno::Enotdir)?;
            let root_at = root_attr.offset;
            let root_id = root_attr.id;
            let root = edit::resident(ATTR_ROOT, &I30_NAME, root_id, false, root_data);
            edit::replace_at(&mut bytes, &header, root_at, &root)?;
            let id = edit::take_attr_id(&mut bytes);
            let alloc = edit::non_resident(ATTR_ALLOC, &I30_NAME, id, &runs,
                                            clusters << self.geo.cluster_bits,
                                            u64::from(block_size), u64::from(block_size),
                                            self.geo.cluster_bits);
            let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
            edit::insert(&mut bytes, &header, &alloc)?;
            let id = edit::take_attr_id(&mut bytes);
            let bitmap_attr = edit::resident(ATTR_BITMAP, &I30_NAME, id, false, &bitmap);
            let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
            edit::insert(&mut bytes, &header, &bitmap_attr)?;
            self.write_record(parent, &mut bytes)?;
            self.write_runs(&runs, 0, block)
        })();
        if result.is_err() { let _ = self.free_runs(&runs); }
        result
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
