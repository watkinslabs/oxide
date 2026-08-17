//! Dropping the blocks of one index range, leaving the nodes in place.
//!
//! The counterpart of shortening: shortening frees the blocks AND the nodes
//! past a point, because nothing will ever address them again. A hole in the
//! middle keeps its nodes, because the indexes after it are still addressed
//! through them.
//!
//! Nothing here creates a node. A range that runs through part of the file
//! that has none is already a hole, and reserving nodes to record that it is
//! one would make punching a hole in a sparse file COST blocks.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::path::{self, Step};
use crate::uapi::*;
use crate::volume::dnode::Holder;
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// The node holding block `index` of `ino`, or `None` where the tree does
    /// not reach that far.
    ///
    /// The read-only twin of the write path's lookup. Asking the write path
    /// would ALLOCATE every node between here and the index, which is the
    /// opposite of what a caller that is about to free blocks wants.
    /// # C: O(indirection depth) blocks
    pub(crate) fn dnode_for_read(&self, ino: u32, index: u64)
        -> Result<Option<(Holder, usize)>, Errno> {
        let inode = self.read_inode(ino)?;
        let Some(p) = path::node_path(inode.addrs_per_inode(), index) else { return Ok(None) };
        let child = |parent: u32, slot: usize| -> Result<u32, Errno> {
            let block = self.read_node(parent, Some(ino))?.block;
            Ok(le32(&block, slot * 4).unwrap_or(0))
        };
        Ok(match p.step() {
            Step::InInode { index } => Some((Holder::Inode, index)),
            Step::Direct { nid_slot, index } => match self.inode_slot(ino, nid_slot)? {
                0 => None,
                nid => Some((Holder::Direct(nid), index)),
            },
            Step::Indirect { nid_slot, dnode, index } => match self.inode_slot(ino, nid_slot)? {
                0 => None,
                ind => match child(ind, dnode)? {
                    0 => None,
                    d => Some((Holder::Direct(d), index)),
                },
            },
            Step::DoubleIndirect { nid_slot, indirect, dnode, index } => {
                match self.inode_slot(ino, nid_slot)? {
                    0 => None,
                    outer => match child(outer, indirect)? {
                        0 => None,
                        mid => match child(mid, dnode)? {
                            0 => None,
                            d => Some((Holder::Direct(d), index)),
                        },
                    },
                }
            }
        })
    }

    /// The address block `index` of `ino` currently has, if any.
    /// # C: O(indirection depth) blocks
    pub(crate) fn index_addr(&self, ino: u32, index: u64) -> Result<u32, Errno> {
        match self.dnode_for_read(ino, index)? {
            None => Ok(NULL_ADDR),
            Some((holder, ofs)) => self.holder_addr(ino, holder, ofs),
        }
    }

    /// Free every block of `ino` in `[first, last)`, keeping its nodes.
    ///
    /// The node is rewritten ONCE per node with every address of the range
    /// cleared, and the blocks are released after. A release per address would
    /// cost a fresh block out of the log per address — on a large hole that is
    /// more allocation than the punch frees.
    /// # C: O(nodes the range spans) blocks
    pub(crate) fn truncate_hole(&mut self, ino: u32, first: u64, last: u64)
        -> Result<(), Errno> {
        let mut index = first;
        while index < last {
            let Some((holder, ofs)) = self.dnode_for_read(ino, index)? else {
                // Nothing addresses this index, so nothing addresses the rest
                // of the node it would have sat in either.
                index += 1;
                continue;
            };
            // How far this node reaches, so one rewrite covers as much of the
            // range as it can.
            let width = match holder {
                Holder::Inode => self.read_inode(ino)?.addrs_per_inode(),
                Holder::Direct(_) => DEF_ADDRS_PER_BLOCK,
            };
            let take = (width - ofs).min((last - index) as usize);
            let mut freed = alloc::vec::Vec::new();
            for i in 0..take {
                let addr = self.holder_addr(ino, holder, ofs + i)?;
                if addr == NULL_ADDR { continue; }
                freed.push((ofs + i, addr));
            }
            // The slots are cleared BEFORE the blocks are released, so a crash
            // in the middle leaves blocks nothing points at rather than a file
            // pointing at blocks the allocator has handed out again.
            for &(at, _) in &freed { self.set_holder_addr(ino, holder, at, NULL_ADDR)?; }
            for (_, addr) in freed { self.release_slot(ino, addr)?; }
            index += take as u64;
        }
        Ok(())
    }

    /// Make `[off, off + len)` inside one block read as zeroes, allocating the
    /// block where the range falls in a hole.
    ///
    /// Allocating is the point rather than a side effect: the caller is saying
    /// those bytes ARE zero, which a hole already says — but the edges of a
    /// punch and of a zeroed range are partial blocks whose other half holds
    /// data, so the block has to exist to hold both.
    /// # C: O(BLKSIZE)
    pub(crate) fn fill_zero(&mut self, ino: u32, index: u64, off: usize, len: usize)
        -> Result<(), Errno> {
        if len == 0 { return Ok(()); }
        let zeroes = alloc::vec![0u8; len];
        self.write_one_block(ino, index, off, &zeroes)
    }
}
