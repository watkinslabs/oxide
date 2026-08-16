//! A directory's index: listing it, and finding one name in it.
//!
//! The tree spans two attributes. `$INDEX_ROOT` holds the top and is resident;
//! `$INDEX_ALLOCATION` holds every other node as a fixed-size block, addressed
//! by a block number that is a position within THAT attribute rather than a
//! cluster of the volume. Reading a block at its number times the cluster size
//! works only while the attribute is contiguous and unfragmented, which is
//! exactly the case a small test volume produces and a real one does not.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib::{self, Attribute};
use crate::index::{self, walk::NodeSource, NodeHeader};
use crate::name::FileName;
use crate::record::Reference;
use crate::uapi::*;

use super::Volume;

/// One name in a directory.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirEntry {
    pub name: alloc::string::String,
    pub fname: FileName,
    pub reference: Reference,
}

impl DirEntry {
    /// # C: O(1)
    pub fn is_dir(&self) -> bool { self.fname.is_dir() }
    /// # C: O(1)
    pub fn size(&self) -> u64 { self.fname.data_size }
}

/// One directory's index, ready to be walked.
pub struct DirIndex<'a, S: SectorSource> {
    pub(crate) vol: &'a Volume<S>,
    /// The record the index belongs to, and its attributes.
    pub(crate) bytes: Vec<u8>,
    pub(crate) attrs: Vec<Attribute>,
    pub(crate) root: index::Root,
    /// The root attribute's data, which the header offsets are relative to.
    pub(crate) root_data: Vec<u8>,
    /// The allocation attribute's runs, when the tree has one.
    pub(crate) alloc: Option<Attribute>,
}

impl<S: SectorSource> NodeSource for DirIndex<'_, S> {
    fn root(&self) -> Result<(Vec<u8>, usize, NodeHeader), Errno> {
        Ok((self.root_data.clone(), self.root.header_at, self.root.header))
    }

    fn block(&self, vbn: u64) -> Result<(Vec<u8>, usize, NodeHeader), Errno> {
        let attr = self.alloc.as_ref().ok_or(Errno::Eio)?;
        let size = self.root.block_size;
        // The block number counts CLUSTERS of the allocation attribute when a
        // block is at least a cluster, and blocks otherwise — which is the
        // same offset either way once it is multiplied out.
        let offset = vbn
            .checked_mul(if size >= self.vol.geo.cluster_size {
                u64::from(self.vol.geo.cluster_size)
            } else {
                u64::from(size)
            })
            .ok_or(Errno::Eio)?;
        let mut bytes = vec![0u8; size as usize];
        let got = self.vol.read_attribute(&self.bytes, &self.attrs, attr, offset, &mut bytes)?;
        if got != bytes.len() { return Err(Errno::Eio); }
        crate::fixup::post_read(&mut bytes, false).map_err(|e| e.errno())?;
        let (header, _) = index::parse_block(&bytes, vbn).ok_or(Errno::Eio)?;
        Ok((bytes, IB_OFF_IHDR, header))
    }

    fn indexed_type(&self) -> u32 { self.root.indexed_type }
}

impl<S: SectorSource> Volume<S> {
    /// A directory's index, ready to be walked. # C: O(record bytes)
    pub fn open_index(&self, number: u64) -> Result<DirIndex<'_, S>, Errno> {
        let (bytes, attrs) = self.read_live_record(number)?;
        let root_attr = attrib::find(&attrs, ATTR_ROOT, &I30_NAME).ok_or(Errno::Enotdir)?;
        let root_data = self.attribute_bytes(&bytes, &attrs, root_attr)?;
        let root = index::parse_root(&root_data).ok_or(Errno::Eio)?;
        let alloc = attrib::find(&attrs, ATTR_ALLOC, &I30_NAME).cloned();
        Ok(DirIndex { vol: self, bytes, attrs, root, root_data, alloc })
    }

    /// Every name in a directory.
    ///
    /// A record's DOS alias is suppressed when it also has a long name, or
    /// every such file is listed twice.
    /// # C: O(directory entries)
    pub fn read_dir(&self, number: u64) -> Result<Vec<DirEntry>, Errno> {
        let idx = self.open_index(number)?;
        let entries = index::walk::walk_all(&idx)?;
        let mut out: Vec<DirEntry> = Vec::new();
        // Which records carry a long name, so an alias beside one is dropped.
        let mut long: Vec<u64> = Vec::new();
        for e in &entries {
            if let Some(f) = e.name() {
                if f.namespace != FILE_NAME_DOS { long.push(e.reference.number); }
            }
        }
        for e in entries {
            let Some(fname) = e.name().cloned() else { continue };
            if !crate::name::should_list(&fname, long.contains(&e.reference.number)) { continue; }
            out.push(DirEntry { name: fname.name(), fname, reference: e.reference });
        }
        Ok(out)
    }

    /// Find one name in a directory, by descent. # C: O(depth)
    pub fn find_entry(&self, number: u64, name: &str) -> Result<DirEntry, Errno> {
        let units = crate::name::encode(name).ok_or(Errno::Enametoolong)?;
        let idx = self.open_index(number)?;
        let hit = index::walk::find(&idx, &units, &self.upcase)?.ok_or(Errno::Enoent)?;
        let fname = hit.name().cloned().ok_or(Errno::Enoent)?;
        Ok(DirEntry { name: fname.name(), fname, reference: hit.reference })
    }

    /// Whether a directory holds any name. # C: O(directory entries)
    pub fn dir_is_empty(&self, number: u64) -> Result<bool, Errno> {
        Ok(self.read_dir(number)?.is_empty())
    }

    /// Resolve a slash-separated path from the root.
    /// # C: O(components * depth)
    pub fn lookup(&self, path: &str) -> Result<DirEntry, Errno> {
        let mut at = MFT_REC_ROOT;
        let mut found: Option<DirEntry> = None;
        for component in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            let hit = self.find_entry(at, component)?;
            at = hit.reference.number;
            found = Some(hit);
        }
        found.ok_or(Errno::Enoent)
    }
}
