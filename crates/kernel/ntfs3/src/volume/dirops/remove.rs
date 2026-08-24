//! Taking an entry out of a directory's index.
//!
//! The entry that carries a CHILD pointer cannot simply go: the subtree below
//! it would be unreachable. Removing such an entry means promoting a key out
//! of the child in its place, which is the mirror of a split — so an entry
//! with a child is refused here rather than dropped with its subtree.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib;
use crate::index::{self, entry};
use crate::uapi::*;

use super::insert::rebuild_node;
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Take the entry named `units` out of `parent`'s index. # C: O(index bytes)
    pub(crate) fn index_remove(&mut self, parent: u64, units: &[u16]) -> Result<(), Errno> {
        let (bytes, attrs) = self.read_live_record(parent)?;
        let root_attr = attrib::find(&attrs, ATTR_ROOT, &I30_NAME).cloned().ok_or(Errno::Enotdir)?;
        let root_data = self.attribute_bytes(&bytes, &attrs, &root_attr)?;
        let root = index::parse_root(&root_data).ok_or(Errno::Eio)?;
        if root.header.has_subnodes() {
            let idx = self.open_index(parent)?;
            let mut ordered: Vec<Vec<u8>> = Vec::new();
            self.collect_index_node(&idx, &idx.root_data, root.header_at, &root.header,
                                    root.indexed_type, &mut ordered)?;
            let mut removed = false;
            let mut kept: Vec<Vec<u8>> = Vec::new();
            for raw in ordered {
                if !removed && entry::parse(&raw, 0, root.indexed_type)
                    .and_then(|e| e.name().map(|n| n.units == units)).unwrap_or(false) {
                    removed = true;
                } else {
                    kept.push(raw);
                }
            }
            if !removed { return Err(Errno::Enoent); }
            self.sort_index_entries_for_remove(&mut kept, root.indexed_type);
            return self.rebuild_index_entries(parent, &idx.root_data, &root, kept);
        }

        let existing = entry::entries(&root_data, root.header_at, &root.header, root.indexed_type);
        let mut ordered: Vec<Vec<u8>> = Vec::new();
        let mut last: Vec<u8> = entry::build_last(None);
        let mut found = false;
        for e in &existing {
            let span = &root_data[e.offset..e.offset + usize::from(e.size)];
            if e.is_last() { last = span.to_vec(); continue; }
            // The FIRST match only: a rename writes the new name before it
            // takes the old one out, so a directory can legitimately hold two
            // entries of one name for the width of that operation — and
            // dropping both leaves neither.
            let matches = !found && e.name().is_some_and(|f| f.units == units);
            if matches {
                // An entry with a subtree cannot be dropped: the keys below it
                // would become unreachable.
                if e.has_child() { return Err(Errno::Enospc); }
                found = true;
                continue;
            }
            ordered.push(span.to_vec());
        }
        if !found { return Err(Errno::Enoent); }

        let head = &root_data[..IROOT_OFF_IHDR];
        let body_total = ordered.iter().map(|e| e.len()).sum::<usize>() + last.len()
            + SIZEOF_IHDR;
        let node = rebuild_node(&ordered, &last, root.header_at, body_total as u32,
                                root.header.flags).ok_or(Errno::Eio)?;
        let mut data = Vec::with_capacity(head.len() + node.len());
        data.extend_from_slice(head);
        data.extend_from_slice(&node);
        self.replace_index_root(parent, &data)
    }

    fn sort_index_entries_for_remove(&self, entries: &mut [Vec<u8>], indexed_type: u32) {
        entries.sort_by(|a, b| {
            let aa = entry::parse(a, 0, indexed_type).and_then(|e| e.name().cloned());
            let bb = entry::parse(b, 0, indexed_type).and_then(|e| e.name().cloned());
            match (aa, bb) {
                (Some(a), Some(b)) => crate::upcase::compare(&a.units, &b.units,
                                                             &self.upcase, false),
                _ => core::cmp::Ordering::Equal,
            }
        });
    }
}
