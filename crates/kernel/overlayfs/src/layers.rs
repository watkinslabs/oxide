//! The stack itself, and which layer each object came from.
//!
//! One overlay object is up to one upper object plus a list of lower ones, and
//! almost every decision the filesystem makes turns on which of those are
//! present: whether a write needs a copy-up first, whether a directory read
//! has to merge, whether a delete can remove a name or must hide it. Keeping
//! that list on the object rather than re-walking the layers is what makes
//! those decisions constant-time — and what makes a stale list a bug that
//! shows up as the wrong file's contents.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use vfs::InodeRef;

use crate::config::Config;
use crate::redirect::Redirect;
use crate::xino;

/// One layer of the stack.
pub struct Layer {
    /// Root directory of the layer.
    pub root: InodeRef,
    /// Position in the stack: zero is the writable layer, one and up are the
    /// lower layers in the order the mount named them.
    pub idx: usize,
    /// One per distinct underlying filesystem, used as the tag when inode
    /// numbers are remapped. Zero is the writable layer's.
    pub fsid: u32,
    /// Holds file contents only; no name ever resolves into it, and only an
    /// absolute redirect reaches it.
    pub data_only: bool,
    /// A directory carrying regular-file whiteouts was found here, so the
    /// slower whiteout check is worth making on this layer. Set once and never
    /// cleared: a layer that had one may have more.
    pub has_xwhiteouts: AtomicBool,
}

impl Layer {
    /// Build a layer descriptor. # C: O(1)
    pub fn new(root: InodeRef, idx: usize, fsid: u32, data_only: bool) -> Arc<Layer> {
        Arc::new(Layer { root, idx, fsid, data_only, has_xwhiteouts: AtomicBool::new(false) })
    }
    /// Is this the writable layer? # C: O(1)
    pub fn is_upper(&self) -> bool { self.idx == 0 }
    /// Record that a directory here carries regular-file whiteouts. # C: O(1)
    pub fn set_xwhiteouts(&self) { self.has_xwhiteouts.store(true, Ordering::Relaxed); }
    /// Is the slower whiteout check worth making here? # C: O(1)
    pub fn xwhiteouts(&self) -> bool { self.has_xwhiteouts.load(Ordering::Relaxed) }
}

/// One object in one layer.
#[derive(Clone)]
pub struct OvlPath {
    pub layer: Arc<Layer>,
    pub inode: InodeRef,
}

/// The whole stack of one mount.
pub struct LayerStack {
    pub config: Config,
    /// Writable layer, absent on a read-only overlay.
    pub upper: Option<Arc<Layer>>,
    /// Lower layers in order, merged ones first and data-only ones last.
    pub lower: Vec<Arc<Layer>>,
    /// Scratch directory for objects mid-construction, on the writable
    /// layer's filesystem. Absent means the mount cannot write.
    pub workdir: Option<InodeRef>,
    /// Directory recording which upper object each lower inode became, so
    /// hardlinks survive copy-up.
    pub indexdir: Option<InodeRef>,
    /// How inode numbers are reported.
    pub xino: xino::Mode,
    /// Longest name any layer accepts.
    pub namelen: u32,
    /// A layer refused to store an attribute, so every feature that needs one
    /// is off for the rest of this mount's life.
    pub noxattr: AtomicBool,
    /// The mount root's own object list. An absolute redirect restarts its
    /// walk here, so it is kept once rather than rebuilt per lookup.
    pub root: OvlEntry,
}

impl LayerStack {
    /// Layers a name may be looked up in, topmost first. # C: O(layers)
    pub fn merged_lower(&self) -> impl Iterator<Item = &Arc<Layer>> {
        self.lower.iter().filter(|l| !l.data_only)
    }
    /// Layers reachable only by an absolute redirect. # C: O(layers)
    pub fn data_layers(&self) -> impl Iterator<Item = &Arc<Layer>> {
        self.lower.iter().filter(|l| l.data_only)
    }
    /// Count of the former. # C: O(layers)
    pub fn num_merged_lower(&self) -> usize { self.merged_lower().count() }
    /// Count of the latter. # C: O(layers)
    pub fn num_data(&self) -> usize { self.data_layers().count() }
    /// Can this mount write at all? # C: O(1)
    pub fn writable(&self) -> bool { self.upper.is_some() && self.workdir.is_some() }
    /// Has a layer refused an attribute write? # C: O(1)
    pub fn noxattr(&self) -> bool { self.noxattr.load(Ordering::Relaxed) }
    /// Record that one has. # C: O(1)
    pub fn set_noxattr(&self) { self.noxattr.store(true, Ordering::Relaxed); }
    /// Does this mount keep an index? # C: O(1)
    pub fn has_index(&self) -> bool { self.indexdir.is_some() }
    /// Is every object indexed, rather than only lower hardlinks? # C: O(1)
    pub fn index_all(&self) -> bool { self.config.nfs_export && self.has_index() }
}

/// What an overlay object is made of.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PathType {
    /// Has an object in the writable layer.
    pub upper: bool,
    /// Reads have to combine layers: a directory with lower halves, or a file
    /// whose data is still below.
    pub merge: bool,
    /// Its identity is that of a lower object it was copied from.
    pub origin: bool,
}

/// One overlay object's layers, and what was found on them.
#[derive(Clone, Default)]
pub struct OvlEntry {
    /// Object in the writable layer.
    pub upper: Option<InodeRef>,
    /// Objects in the lower layers, topmost first. For a non-directory that
    /// was copied up this holds the origin it came from.
    pub lower: Vec<OvlPath>,
    /// The upper directory hides every lower one of the same name.
    pub opaque: bool,
    /// A name in the writable layer really refers to this object, as opposed
    /// to an upper object reached only through the index.
    pub upper_alias: bool,
    /// Some lower directory in the stack carries regular-file whiteouts.
    pub xwhiteouts: bool,
    /// Where the upper object says its lower half lives.
    pub redirect: Option<Redirect>,
    /// The upper object holds metadata only; its data is in the lower layers.
    pub metacopy: bool,
    /// The upper directory holds entries whose lower origin is not their name.
    pub impure: bool,
    /// A directory that does not merge may still contain whiteouts, left from
    /// a time when it did.
    pub whiteouts: bool,
    /// An index entry ties this object to its origin.
    pub indexed: bool,
    /// Where the data of a metadata-only object lives, when it is in a
    /// data-only layer and named by an absolute redirect.
    pub lowerdata_redirect: Option<String>,
}

impl OvlEntry {
    /// What this object is made of.
    ///
    /// A copied-up FILE keeps its origin in the lower list, which is why the
    /// presence of a lower entry alone does not mean the object merges: a
    /// non-directory merges only while its data is still below.
    /// # C: O(1)
    pub fn path_type(&self, is_dir: bool) -> PathType {
        let mut t = PathType::default();
        if self.upper.is_some() {
            t.upper = true;
            if !self.lower.is_empty() {
                t.origin = true;
                if is_dir || self.metacopy { t.merge = true; }
            }
        } else if self.lower.len() > 1 {
            t.merge = true;
        }
        t
    }
    /// The object reads and writes go to: the upper one if there is one, else
    /// the topmost lower one. # C: O(1)
    pub fn real(&self) -> Option<InodeRef> {
        self.upper.clone().or_else(|| self.lower.first().map(|p| p.inode.clone()))
    }
    /// The object holding the DATA, which for a metadata-only upper object is
    /// the bottom of the lower list rather than the top. # C: O(1)
    pub fn realdata(&self) -> Option<InodeRef> {
        if self.upper.is_some() && !self.metacopy { return self.upper.clone(); }
        self.lower.last().map(|p| p.inode.clone()).or_else(|| self.upper.clone())
    }
    /// Topmost lower object, which is the copy-up source and the origin. # C: O(1)
    pub fn lower_top(&self) -> Option<&OvlPath> { self.lower.first() }
    /// Is there anything below to merge or copy from? # C: O(1)
    pub fn has_lower(&self) -> bool { !self.lower.is_empty() }
}

/// Are two layer paths safe to use as upper and work directories?
///
/// Either being inside the other lets the work directory's contents appear in
/// the overlay, or the overlay's contents appear as work in progress; the two
/// being the same is both at once. Compared as paths because this runs before
/// either is resolved, so that a mount naming an impossible pair fails at the
/// option rather than halfway through building a superblock.
/// # C: O(len(a) + len(b))
pub fn dirs_disjoint(a: &str, b: &str) -> bool {
    !under(a, b) && !under(b, a)
}

/// Is `inner` at or below `outer`? # C: O(len(outer))
fn under(inner: &str, outer: &str) -> bool {
    let o = outer.trim_end_matches('/');
    if !inner.starts_with(o) { return false; }
    matches!(inner.as_bytes().get(o.len()), None | Some(b'/'))
}

#[cfg(test)]
#[path = "layers/tests.rs"]
mod tests;
