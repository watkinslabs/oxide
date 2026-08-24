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
use crate::index::walk::NodeSource;
use crate::name::FileName;
use crate::record::Reference;
use crate::run::Runs;
use crate::uapi::*;

use super::{edit, Volume};
use crate::volume::dir::DirIndex;

struct BuildNode {
    entries: Vec<Vec<u8>>,
    children: Vec<BuildNode>,
}

impl BuildNode {
    fn leaf(entries: Vec<Vec<u8>>) -> Self { Self { entries, children: Vec::new() } }

    fn peek_min(&self) -> Option<Vec<u8>> {
        if self.children.is_empty() { self.entries.first().cloned() }
        else { self.children[0].peek_min().or_else(|| self.entries.first().cloned()) }
    }

    fn pop_min(&mut self) -> Option<Vec<u8>> {
        if self.children.is_empty() { return if self.entries.is_empty() { None } else { Some(self.entries.remove(0)) }; }
        if let Some(key) = self.children[0].pop_min() { return Some(key); }
        self.children.remove(0);
        if self.entries.is_empty() { None } else { Some(self.entries.remove(0)) }
    }
}

fn build_node_fits(entries: &[Vec<u8>], size: u32) -> bool {
    let block = index::format_block(size, 0);
    let at = IB_OFF_IHDR;
    let de_off = u32::from_le_bytes(block[at + IHDR_OFF_DE_OFF..at + IHDR_OFF_DE_OFF + 4]
                                     .try_into().unwrap_or([0; 4]));
    rebuild_node_at(entries, &entry::build_last(None), de_off, size - at as u32, 0, at).is_some()
}

fn build_internal_fits(entries: &[Vec<u8>], size: u32) -> bool {
    let block = index::format_block(size, 0);
    let at = IB_OFF_IHDR;
    let de_off = u32::from_le_bytes(block[at + IHDR_OFF_DE_OFF..at + IHDR_OFF_DE_OFF + 4]
                                     .try_into().unwrap_or([0; 4]));
    rebuild_node_at(entries, &entry::build_last(Some(0)), de_off, size - at as u32,
                    INDEX_HDR_HAS_SUBNODES, at).is_some()
}

fn encode_build_node(node: &BuildNode, size: u32, next: &mut u64,
                     blocks: &mut Vec<Vec<u8>>) -> Result<u64, Errno> {
    let mut child_vbns = Vec::new();
    for child in &node.children {
        child_vbns.push(encode_build_node(child, size, next, blocks)?);
    }
    let entries = if node.children.is_empty() {
        node.entries.clone()
    } else {
        let mut out = Vec::new();
        for (raw, vbn) in node.entries.iter().zip(child_vbns.iter().copied()) {
            let parsed = entry::parse(raw, 0, ATTR_NAME).ok_or(Errno::Eio)?;
            let key = raw[SIZEOF_DE..SIZEOF_DE + usize::from(parsed.key_size)].to_vec();
            out.push(entry::build(&parsed.reference, &key, Some(vbn)));
        }
        out
    };
    let last = entry::build_last(child_vbns.last().copied());
    let mut block = index::format_block(size, *next);
    let at = IB_OFF_IHDR;
    let de_off = u32::from_le_bytes(block[at + IHDR_OFF_DE_OFF..at + IHDR_OFF_DE_OFF + 4]
                                     .try_into().map_err(|_| Errno::Eio)?);
    let node_bytes = rebuild_node_at(&entries, &last, de_off, size - at as u32,
                                     if node.children.is_empty() { 0 } else { INDEX_HDR_HAS_SUBNODES }, at)
        .ok_or(Errno::Enospc)?;
    block[at..at + node_bytes.len()].copy_from_slice(&node_bytes);
    crate::fixup::pre_write(&mut block, 1).map_err(|e| e.errno())?;
    let vbn = *next;
    *next += 1;
    blocks.push(block);
    Ok(vbn)
}

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
    fn index_insert_allocation(&mut self, parent: u64, new_entry: &[u8], _fname: &FileName,
                               root: &index::Root) -> Result<(), Errno> {
        let idx = self.open_index(parent)?;
        let mut ordered = Vec::new();
        self.collect_index_node(&idx, &idx.root_data, root.header_at, &root.header,
                                root.indexed_type, &mut ordered)?;
        ordered.push(new_entry.to_vec());
        self.sort_index_entries(&mut ordered, root.indexed_type);
        self.rebuild_index_entries(parent, &idx.root_data, root, ordered)
    }

    pub(crate) fn collect_index_node(&self, idx: &DirIndex<'_, S>, bytes: &[u8], at: usize,
                          header: &index::NodeHeader, indexed_type: u32,
                          out: &mut Vec<Vec<u8>>) -> Result<(), Errno> {
        for item in entry::entries(bytes, at, header, indexed_type) {
            if let Some(vbn) = item.child {
                let (child, child_at, child_header) = idx.block(vbn)?;
                self.collect_index_node(idx, &child, child_at, &child_header, indexed_type, out)?;
            }
            if item.is_last() { continue; }
            let raw = &bytes[item.offset..item.offset + usize::from(item.size)];
            out.push(if item.has_child() {
                self.without_child(raw, indexed_type)?
            } else {
                raw.to_vec()
            });
        }
        Ok(())
    }

    pub(crate) fn rebuild_index_entries(&mut self, parent: u64, root_data: &[u8],
                                        root: &index::Root, ordered: Vec<Vec<u8>>)
        -> Result<(), Errno> {
        let mut leaves = Vec::new();
        let mut at = 0usize;
        while at < ordered.len() {
            let mut end = at + 1;
            while end <= ordered.len() && build_node_fits(&ordered[at..end], root.block_size) {
                end += 1;
            }
            let take_end = end.saturating_sub(1);
            if take_end <= at { return Err(Errno::Enospc); }
            leaves.push(BuildNode::leaf(ordered[at..take_end].to_vec()));
            at = take_end;
        }
        if leaves.is_empty() { leaves.push(BuildNode::leaf(Vec::new())); }

        let (bytes, header) = self.read_record_raw(parent)?;
        let attrs = attrib::parse_all(&bytes, &header);
        let root_attr = attrib::find(&attrs, ATTR_ROOT, &I30_NAME)
            .ok_or(Errno::Enotdir)?;
        let root_capacity = edit::free_space(&bytes, &header) + root_attr.size as usize;
        let mut level = leaves;
        loop {
            let mut root_entries = Vec::new();
            for child in level.iter().skip(1) {
                let raw = child.peek_min().ok_or(Errno::Eio)?;
                let parsed = entry::parse(&raw, 0, root.indexed_type).ok_or(Errno::Eio)?;
                let key = raw[SIZEOF_DE..SIZEOF_DE + usize::from(parsed.key_size)].to_vec();
                root_entries.push(entry::build(&parsed.reference, &key, Some(0)));
            }
            let root_last = entry::build_last(Some((level.len() - 1) as u64));
            let root_node = rebuild_node(&root_entries, &root_last, root.header_at,
                                         (SIZEOF_IHDR + root_entries.iter().map(Vec::len)
                                             .sum::<usize>() + root_last.len()) as u32,
                                         INDEX_HDR_HAS_SUBNODES).ok_or(Errno::Enospc)?;
            let root_candidate = edit::resident(ATTR_ROOT, &I30_NAME, root_attr.id, false,
                                                 &[&root_data[..IROOT_OFF_IHDR], &root_node].concat());
            if root_candidate.len() <= root_capacity {
                let mut separators = Vec::new();
                for child in level.iter().skip(1) {
                    separators.push(child.peek_min().ok_or(Errno::Eio)?);
                }
                for child in level.iter_mut().skip(1) {
                    let _ = child.pop_min().ok_or(Errno::Eio)?;
                }
                let mut blocks = Vec::new();
                let mut next = 0;
                let mut child_vbns = Vec::new();
                for child in &level {
                    child_vbns.push(encode_build_node(child, root.block_size, &mut next,
                                                       &mut blocks)?);
                }
                let mut root_entries = Vec::new();
                for (i, sep) in separators.iter().enumerate() {
                    let parsed = entry::parse(&sep, 0, root.indexed_type).ok_or(Errno::Eio)?;
                    let key = sep[SIZEOF_DE..SIZEOF_DE + usize::from(parsed.key_size)].to_vec();
                    root_entries.push(entry::build(&parsed.reference, &key, Some(child_vbns[i])));
                }
                let root_last = entry::build_last(child_vbns.last().copied());
                let root_node = rebuild_node(&root_entries, &root_last, root.header_at,
                                             (SIZEOF_IHDR + root_entries.iter().map(Vec::len)
                                                 .sum::<usize>() + root_last.len()) as u32,
                                             INDEX_HDR_HAS_SUBNODES).ok_or(Errno::Enospc)?;
                let mut new_root = Vec::with_capacity(IROOT_OFF_IHDR + root_node.len());
                new_root.extend_from_slice(&root_data[..IROOT_OFF_IHDR]);
                new_root.extend_from_slice(&root_node);
                return self.rewrite_index_allocation(parent, &new_root, root.block_size, &blocks);
            }
            level = self.group_build_nodes(level, root.block_size)?;
        }
    }

    fn group_build_nodes(&self, mut children: Vec<BuildNode>, block_size: u32)
        -> Result<Vec<BuildNode>, Errno> {
        let mut parents = Vec::new();
        while !children.is_empty() {
            let first = children.remove(0);
            let mut group = vec![first];
            let mut entries = Vec::new();
            while !children.is_empty() {
                let separator = children[0].peek_min().ok_or(Errno::Eio)?;
                let parsed = entry::parse(&separator, 0, ATTR_NAME).ok_or(Errno::Eio)?;
                let key = separator[SIZEOF_DE..SIZEOF_DE + usize::from(parsed.key_size)].to_vec();
                let candidate = entry::build(&parsed.reference, &key, Some(0));
                let mut test = entries.clone();
                test.push(candidate);
                if !build_internal_fits(&test, block_size) { break; }
                entries.push(test.pop().ok_or(Errno::Eio)?);
                group.push(children.remove(0));
            }
            // Store separators without child pointers; encode_build_node adds
            // the finalized VCNs after all descendants have been assigned.
            for entry in &mut entries {
                let parsed = entry::parse(entry, 0, ATTR_NAME).ok_or(Errno::Eio)?;
                let key = entry[SIZEOF_DE..SIZEOF_DE + usize::from(parsed.key_size)].to_vec();
                *entry = entry::build(&parsed.reference, &key, None);
            }
            parents.push(BuildNode { entries, children: group });
        }
        Ok(parents)
    }

    fn without_child(&self, raw: &[u8], indexed_type: u32) -> Result<Vec<u8>, Errno> {
        let parsed = entry::parse(raw, 0, indexed_type).ok_or(Errno::Eio)?;
        let key = raw[SIZEOF_DE..SIZEOF_DE + usize::from(parsed.key_size)].to_vec();
        Ok(entry::build(&parsed.reference, &key, None))
    }

    fn sort_index_entries(&self, entries: &mut [Vec<u8>], indexed_type: u32) {
        entries.sort_by(|a, b| {
            let aa = entry::parse(a, 0, indexed_type).and_then(|e| e.name().cloned());
            let bb = entry::parse(b, 0, indexed_type).and_then(|e| e.name().cloned());
            match (aa, bb) {
                (Some(a), Some(b)) => crate::upcase::compare(&a.units, &b.units, &self.upcase, false),
                _ => core::cmp::Ordering::Equal,
            }
        });
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

    fn rewrite_index_allocation(&mut self, parent: u64, root_data: &[u8], block_size: u32,
                                blocks: &[Vec<u8>]) -> Result<(), Errno> {
        let (mut bytes, header) = self.read_record_raw(parent)?;
        let attrs = attrib::parse_all(&bytes, &header);
        let root_attr = attrib::find(&attrs, ATTR_ROOT, &I30_NAME).ok_or(Errno::Enotdir)?;
        let root = edit::resident(ATTR_ROOT, &I30_NAME, root_attr.id, false, root_data);
        edit::replace_at(&mut bytes, &header, root_attr.offset, &root)?;

        let attrs = attrib::parse_all(&bytes, &crate::record::parse(&bytes)
            .map_err(|e| e.errno())?);
        let alloc_attr = attrib::find(&attrs, ATTR_ALLOC, &I30_NAME).ok_or(Errno::Eio)?;
        let old_runs = self.attribute_runs(&bytes, &attrs, alloc_attr)?;
        let need = self.geo.clusters_for(u64::from(block_size) * blocks.len() as u64);
        let mut runs = old_runs.clone();
        let mut dropped = Runs::new();
        if need > runs.clusters() {
            let extra = self.alloc_clusters(need - runs.clusters())?;
            let base = runs.clusters();
            for mut run in extra.runs { run.vcn += base; runs.push(run); }
        } else if need < runs.clusters() {
            let mut kept = Runs::new();
            for run in &runs.runs {
                if run.vcn >= need { dropped.push(*run); continue; }
                if run.vcn + run.len <= need { kept.push(*run); continue; }
                let split = need - run.vcn;
                kept.push(crate::run::Run { vcn: run.vcn, lcn: run.lcn, len: split });
                dropped.push(crate::run::Run {
                    vcn: run.vcn + split,
                    lcn: run.lcn + split,
                    len: run.len - split,
                });
            }
            runs = kept;
        }
        let alloc = edit::non_resident(ATTR_ALLOC, &I30_NAME, alloc_attr.id, &runs,
                                        runs.clusters() << self.geo.cluster_bits,
                                        u64::from(block_size) * blocks.len() as u64,
                                        u64::from(block_size) * blocks.len() as u64,
                                        self.geo.cluster_bits);
        let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
        let alloc_at = attrib::find(&attrib::parse_all(&bytes, &header), ATTR_ALLOC, &I30_NAME)
            .ok_or(Errno::Eio)?.offset;
        edit::replace_at(&mut bytes, &header, alloc_at, &alloc)?;
        let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
        let attrs = attrib::parse_all(&bytes, &header);
        let bitmap_attr = attrib::find(&attrs, ATTR_BITMAP, &I30_NAME)
            .ok_or(Errno::Eio)?;
        let mut bitmap = alloc::vec![0u8; (blocks.len() + 7) / 8];
        for bit in 0..blocks.len() { bitmap[bit / 8] |= 1u8 << (bit % 8); }
        let bitmap_new = edit::resident(ATTR_BITMAP, &I30_NAME, bitmap_attr.id, false, &bitmap);
        edit::replace_at(&mut bytes, &header, bitmap_attr.offset, &bitmap_new)?;
        let result = (|| {
            self.write_record(parent, &mut bytes)?;
            for (i, block) in blocks.iter().enumerate() {
                self.write_runs(&runs, u64::from(block_size) * i as u64, block)?;
            }
            if !dropped.runs.is_empty() { self.free_runs(&dropped)?; }
            Ok(())
        })();
        if result.is_err() && need > old_runs.clusters() {
            let mut added = Runs::new();
            for run in &runs.runs {
                if run.vcn >= old_runs.clusters() { added.push(*run); }
            }
            let _ = self.free_runs(&added);
        }
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
