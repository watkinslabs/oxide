//! What changed about one file since the last checkpoint, and which side of
//! the file it changed.
//!
//! `fsync` and `fdatasync` are not the same promise. Both make the file's DATA
//! durable; only the first also promises the times and the mode. A build that
//! treats them alike either writes a chain nobody asked for on every timestamp
//! touch, or — the expensive direction — reports durability for a size it never
//! wrote. So the state has to be split in two, and the split has to be read
//! from something that cannot drift.
//!
//! Nothing here is cached. This build writes an inode THROUGH: a change to the
//! mode reaches the medium as a new inode block before the caller returns, and
//! what makes it unsafe is only that the node table on the medium still names
//! the block it replaced. That is also what makes the answer derivable — both
//! generations of the block are on the medium at once, so "what changed" is a
//! comparison, not a flag somebody has to remember to set. A flag would be a
//! second copy of a truth the medium already holds, and the two would
//! eventually disagree.
//!
//! Two predicates come out of the same place and must not be confused. Whether
//! a node EXISTED at the last checkpoint decides whether a directory entry has
//! to be restored for it; whether a node was WRITTEN since then decides
//! whether the parent's attribute or directory blocks are only in the chain. A
//! rewrite makes the second true and leaves the first true, and using one for
//! the other turns every ordinary write into a checkpoint.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::EXTRA_ATTR;
use crate::nat;
use crate::node::footer;
use crate::uapi::*;

use crate::volume::Volume;

/// Which side of a file changed since the last checkpoint.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Dirty {
    /// The file's contents, its length, or the nodes that reach them.
    pub data: bool,
    /// Only what a data sync is allowed to leave behind: the times, the mode
    /// and the owning identities.
    pub meta: bool,
}

impl Dirty {
    /// Nothing about the file reached the medium since the checkpoint.
    /// # C: O(1)
    pub fn clean(self) -> bool { !self.data && !self.meta }

    /// Whether a sync of this kind has anything to make durable.
    ///
    /// A data sync that finds only metadata dirty writes nothing at all: the
    /// contents are already as durable as the last checkpoint left them, and
    /// the times are not part of what it promised.
    /// # C: O(1)
    pub fn needs_sync(self, datasync: bool) -> bool {
        if datasync { self.data } else { !self.clean() }
    }
}

/// Everything a data sync may leave behind, as `(offset, length)` runs of the
/// inode block: the mode, the two identities, and the three times with their
/// nanosecond halves.
const META_RUNS: [(usize, usize); 3] =
    [(I_MODE, 2), (I_UID, 8), (I_ATIME, I_GENERATION - I_ATIME)];

/// The checksum covers the whole block, so it differs whenever anything does
/// and says nothing about WHAT. It is compared as neither side.
const CHECKSUM_RUN: (usize, usize) = (I_INODE_CHECKSUM, 4);

/// Whether `at` falls in one of the runs.
fn in_runs(runs: &[(usize, usize)], at: usize) -> bool {
    runs.iter().any(|&(start, len)| at >= start && at < start + len)
}

/// Compare the checkpointed generation of an inode block with the current one.
///
/// Every byte outside the metadata runs counts as data — the address array,
/// the length, the node ids, the inline body and every field this build does
/// not yet name. That direction is deliberate: an unrecognised field that
/// changed is synced, where the other default would silently drop it.
///
/// `extra` says whether the inode carries the extra-attribute region, because
/// without it the four bytes the checksum would occupy are the third and
/// fourth ADDRESSES of the file, and skipping them there would hide a write.
/// # C: O(BLKSIZE)
pub fn block_dirty(prev: &[u8], cur: &[u8], extra: bool) -> Dirty {
    if prev.len() < NODE_FOOTER_OFF || cur.len() < NODE_FOOTER_OFF {
        return Dirty { data: true, meta: true };
    }
    let mut d = Dirty::default();
    for at in 0..NODE_FOOTER_OFF {
        if prev[at] == cur[at] { continue; }
        if extra && in_runs(&[CHECKSUM_RUN], at) { continue; }
        if in_runs(&META_RUNS, at) { d.meta = true; } else { d.data = true; }
    }
    d
}

impl<S: SectorSource> Volume<S> {
    /// The address the node table gave for `nid` at the last checkpoint.
    ///
    /// Deliberately NOT [`Volume::node_addr`], which answers with what this
    /// mount has written. The question here is what a crash would leave, and
    /// that is the table on the medium plus the journal the checkpoint parked
    /// with it.
    /// # C: O(journal entries + 1 block)
    pub(crate) fn checkpointed_node_addr(&self, nid: u32) -> Result<u32, Errno> {
        if !nat::nid_in_range(nid, self.max_nid()) { return Err(Errno::Einval); }
        if let Some(e) = nat::journalled(&self.nat_journal, nid) { return Ok(e.block_addr); }
        let at = nat::block_addr(
            self.sb.nat_blkaddr,
            self.sb.blks_per_seg(),
            nid,
            &self.nat_bitmap,
        );
        let block = self.read_block(at)?;
        let entry = nat::resolve(&self.nat_journal, &block, nid).ok_or(Errno::Eio)?;
        Ok(entry.block_addr)
    }

    /// Whether the node `nid` names existed at the last checkpoint.
    ///
    /// A node this mount CREATED is only in memory, so nothing a reader could
    /// do after a crash would find it and any name pointing at it has to be
    /// restored. A node this mount merely rewrote is a different matter: the
    /// checkpoint still names its previous block, so the node is there and
    /// only its contents are behind.
    /// # C: O(journal entries + 1 block)
    pub(crate) fn node_is_checkpointed(&self, nid: u32) -> bool {
        match self.checkpointed_node_addr(nid) {
            Ok(addr) => !crate::node::is_hole(addr),
            Err(_) => false,
        }
    }

    /// Whether `nid` was written since the last checkpoint, whether or not it
    /// existed before it. # C: O(log dirty nodes)
    pub(crate) fn node_written_since_checkpoint(&self, nid: u32) -> bool {
        self.nat_dirty.contains_key(&nid)
    }

    /// Whether any node BELOW `ino` was written since the last checkpoint.
    ///
    /// This is what catches an overwrite. Rewriting a block that already
    /// existed moves it, which rewrites the direct node holding its address —
    /// but leaves the inode's own bytes carrying nothing but a new mtime. Read
    /// off the inode alone, such a write looks like a timestamp touch, and a
    /// data sync would return having written nothing.
    /// # C: O(dirty nodes)
    pub(crate) fn file_nodes_written(&self, ino: u32) -> bool {
        self.nat_dirty.iter().any(|(&nid, e)| nid != ino && e.ino == ino)
    }

    /// The inode block the last checkpoint still names, when it can be trusted.
    ///
    /// The block is only released, never erased, so it is normally still
    /// readable — but a released block may have been handed out again inside
    /// this mount, and reading whatever landed there as an inode would compare
    /// against another file. The footer is what settles it.
    /// # C: O(1 block)
    fn checkpointed_inode_block(&self, ino: u32) -> Option<Vec<u8>> {
        let addr = self.checkpointed_node_addr(ino).ok()?;
        if crate::node::is_hole(addr) || !self.sb.valid_main_blkaddr(addr) { return None; }
        let block = self.read_block(addr).ok()?;
        let f = footer::expect(&block, ino, Some(ino)).ok()?;
        if !f.is_inode() { return None; }
        Some(block)
    }

    /// What about `ino` is not yet durable, split by which sync promises it.
    ///
    /// An inode the checkpoint has never seen is dirty on both sides by
    /// construction: there is no previous generation to differ from, and every
    /// byte of it would be lost.
    /// # C: O(1 block)
    pub(crate) fn inode_dirty(&self, ino: u32) -> Result<Dirty, Errno> {
        let (inode, node) = self.read_inode_ref(ino)?;
        let mut d = match self.checkpointed_inode_block(ino) {
            Some(prev) => block_dirty(&prev, &node.block, inode.has(EXTRA_ATTR)),
            None => Dirty { data: true, meta: true },
        };
        if !d.data && self.file_nodes_written(ino) { d.data = true; }
        Ok(d)
    }
}

#[cfg(test)]
#[path = "../../tests/fsync/dirty.rs"]
mod tests;
