//! Putting one file's node blocks into the log as a chain a later mount can
//! follow.
//!
//! Which blocks: the inode, and every DIRECT node under it. The indirect nodes
//! are deliberately left out — they carry node ids, not block addresses, and
//! replay rebuilds them from the addresses it recovers, so writing them would
//! add links to the chain that say nothing.
//!
//! Two stamps make the chain. Each block gets the fsync mark, so replay can
//! tell blocks a caller was promised from blocks that merely happened to be
//! written; and each block's forward pointer gets the address the log will
//! hand out NEXT, so the walk advances. A block whose forward pointer names
//! itself is a chain of length one no matter how much followed it.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::Inode;
use crate::uapi::*;
use crate::volume::curseg::Kind;
use crate::volume::recover::marks;
use crate::volume::Volume;

/// The tree offset of the first of the two direct nodes an inode names.
const FIRST_DIRECT_OFS: u32 = 1;
/// The tree offset of the first indirect node.
const FIRST_INDIRECT_OFS: u32 = 3;
/// How many of the inode's five slots name direct nodes, and where the
/// indirect and double-indirect ones begin.
const DIRECT_SLOTS: usize = 2;
const INDIRECT_SLOTS: usize = 4;
const DINDIRECT_SLOT: usize = 4;

impl<S: SectorSource> Volume<S> {
    /// Every node of `ino` that holds block addresses, with its tree offset,
    /// the inode first. # C: O(nodes the file has) blocks
    pub(crate) fn fsync_dnodes(&self, ino: u32, inode: &Inode) -> Result<Vec<(u32, u32)>, Errno> {
        let nids = NIDS_PER_BLOCK as u32;
        let block = self.inode_bytes(ino)?;
        let mut out: Vec<(u32, u32)> = alloc::vec![(ino, 0)];
        for slot in 0..DIRECT_SLOTS {
            let nid = inode.nid(&block, slot).unwrap_or(0);
            if nid != 0 { out.push((nid, FIRST_DIRECT_OFS + slot as u32)); }
        }
        for slot in DIRECT_SLOTS..INDIRECT_SLOTS {
            let nid = inode.nid(&block, slot).unwrap_or(0);
            if nid == 0 { continue; }
            let base = if slot == DIRECT_SLOTS { FIRST_INDIRECT_OFS } else { 4 + nids };
            self.push_children(ino, nid, base, &mut out)?;
        }
        let nid = inode.nid(&block, DINDIRECT_SLOT).unwrap_or(0);
        if nid != 0 {
            let base = 5 + 2 * nids;
            let outer = self.read_node(nid, Some(ino))?.block;
            for i in 0..NIDS_PER_BLOCK {
                let mid = crate::node::indirect_nid(&outer, i).unwrap_or(0);
                if mid == 0 { continue; }
                let mid_ofs = base + 1 + i as u32 * (nids + 1);
                self.push_children(ino, mid, mid_ofs, &mut out)?;
            }
        }
        Ok(out)
    }

    /// Add every direct node one indirect node names. # C: O(1 block)
    fn push_children(&self, ino: u32, nid: u32, base: u32, out: &mut Vec<(u32, u32)>)
        -> Result<(), Errno> {
        let block = self.read_node(nid, Some(ino))?.block;
        for i in 0..NIDS_PER_BLOCK {
            let child = crate::node::indirect_nid(&block, i).unwrap_or(0);
            if child != 0 { out.push((child, base + 1 + i as u32)); }
        }
        Ok(())
    }

    /// Write one node block into the file-node log, marked and chained.
    ///
    /// Only the marks are stamped here. The forward pointer belongs to the
    /// node writer, which fills it in from the log's position after the block
    /// has been allocated — the one place that knows where the log goes next.
    ///
    /// PLACED at once, rather than left dirty for the next flush. A chain is
    /// read forward from where the log stood at the last checkpoint, so the
    /// order the blocks reach the medium in IS the chain; leaving them to a
    /// later flush would let the mapping choose that order, and an inode
    /// arriving after the nodes under it is a chain replay cannot size.
    /// # C: O(1 block)
    pub(crate) fn write_chained_node(&mut self, nid: u32, ino: u32, block: Vec<u8>, flag: u32)
        -> Result<u32, Errno> {
        let mut block = block;
        marks::set_flag(&mut block, flag);
        self.write_node(nid, ino, block, Kind::FileNode)?;
        self.writeback_node(nid)
    }

    /// Put the whole file into the log, inode first.
    ///
    /// The inode leads because replay needs the file's size and mode before it
    /// can decide which of the addresses under it are inside the file at all.
    /// # C: O(nodes the file has) blocks
    pub(crate) fn write_fsync_chain(&mut self, ino: u32, dent: bool) -> Result<u32, Errno> {
        let inode = self.read_inode(ino)?;
        let list = self.fsync_dnodes(ino, &inode)?;
        let mut written = 0;
        for (nid, ofs) in list {
            let is_inode = nid == ino;
            let block = if is_inode {
                self.inode_bytes(ino)?
            } else {
                self.read_node(nid, Some(ino))?.block
            };
            let flag = marks::flag_word(ofs, true, dent && is_inode, true);
            self.write_chained_node(nid, ino, block, flag)?;
            written += 1;
        }
        Ok(written)
    }
}

#[cfg(test)]
#[path = "../../tests/fsync/deep.rs"]
mod tests;
