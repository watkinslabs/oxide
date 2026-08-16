//! Freeing what a shortened — or deleted — file no longer needs.
//!
//! Releasing a file's data blocks is only half of shortening it. The direct
//! and indirect nodes that held their addresses are blocks too, and one left
//! behind with every address cleared is unreachable and still counted live —
//! a leak the segment table cannot see, because from its side the block is
//! perfectly in use.
//!
//! The walk is over the TREE, never over the index range. A sparse file may be
//! terabytes long with three blocks in it, and stepping index by index would
//! do millions of lookups to find nothing; the tree has one entry per block
//! that exists.
//!
//! A node is freed only when its ENTIRE range is gone. One still covering a
//! surviving block keeps its slot, and only the addresses inside it are
//! cleared.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;

use super::curseg::Kind;
use super::Volume;

/// Where each of the five node slots' ranges begins, for an inode `apb` wide.
/// # C: O(1)
fn slot_bases(apb: u64) -> [u64; 5] {
    let d = DEF_ADDRS_PER_BLOCK as u64;
    let p = NIDS_PER_BLOCK as u64;
    [apb, apb + d, apb + 2 * d, apb + 2 * d + d * p, apb + 2 * d + 2 * d * p]
}

impl<S: SectorSource> Volume<S> {
    /// Drop every block and node of `ino` from file index `first_gone` on.
    /// # C: O(blocks and nodes the file has)
    pub(crate) fn truncate_tail(&mut self, ino: u32, first_gone: u64) -> Result<(), Errno> {
        // Whole node subtrees go here, not one address at a time, so the
        // per-address notification the write path relies on never fires for
        // them. Everything from the cut is invalidated in one range instead:
        // a remembered run over blocks this file no longer owns would answer a
        // read past the end of the file with someone else's data.
        self.forget_extents_from(ino, first_gone);
        let inode = self.read_inode(ino)?;
        let apb = inode.addrs_per_inode() as u64;
        let d = DEF_ADDRS_PER_BLOCK as u64;
        let p = NIDS_PER_BLOCK as u64;
        let bases = slot_bases(apb);

        if first_gone < apb {
            let base_off = inode.addr_base();
            let mut block = self.inode_bytes(ino)?;
            let mut freed = Vec::new();
            for i in first_gone..apb {
                let at = base_off + i as usize * 4;
                let addr = le32(&block, at).unwrap_or(NULL_ADDR);
                if addr == NULL_ADDR { continue; }
                block[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
                freed.push(addr);
            }
            if !freed.is_empty() {
                self.put_inode(ino, block)?;
                for addr in freed { self.release_slot(ino, addr)?; }
            }
        }
        for slot in 0..2usize {
            self.trim_slot(ino, slot, bases[slot], d, first_gone, 0)?;
        }
        for slot in 2..4usize {
            self.trim_slot(ino, slot, bases[slot], d * p, first_gone, 1)?;
        }
        self.trim_slot(ino, 4, bases[4], d * p * p, first_gone, 2)
    }

    /// Free or trim whatever one of the inode's five slots names.
    /// # C: O(subtree)
    fn trim_slot(&mut self, ino: u32, slot: usize, base: u64, span: u64, first_gone: u64,
                 depth: u8) -> Result<(), Errno> {
        let nid = self.inode_slot(ino, slot)?;
        if nid == 0 { return Ok(()); }
        if first_gone <= base {
            self.free_subtree(ino, nid, depth)?;
            return self.clear_inode_slot(ino, slot);
        }
        if first_gone >= base + span { return Ok(()); }
        self.trim_node(ino, nid, base, first_gone, depth)
    }

    /// Trim inside a node that survives.
    ///
    /// Children whose whole range is gone are unhooked and freed; one that
    /// straddles the cut is trimmed in turn. The parent is rewritten ONCE,
    /// before the children are freed, so a crash in the middle leaves blocks
    /// nothing points at rather than pointers to freed blocks.
    /// # C: O(subtree)
    fn trim_node(&mut self, ino: u32, nid: u32, base: u64, first_gone: u64, depth: u8)
        -> Result<(), Errno> {
        let d = DEF_ADDRS_PER_BLOCK as u64;
        let p = NIDS_PER_BLOCK as u64;
        let mut block = self.read_node(nid, Some(ino))?.block;
        let mut changed = false;
        if depth == 0 {
            let mut freed = Vec::new();
            for i in 0..DEF_ADDRS_PER_BLOCK {
                if base + (i as u64) < first_gone { continue; }
                let addr = crate::node::direct_addr(&block, i).unwrap_or(NULL_ADDR);
                if addr == NULL_ADDR { continue; }
                block[i * 4..i * 4 + 4].copy_from_slice(&0u32.to_le_bytes());
                freed.push(addr);
                changed = true;
            }
            if changed { self.write_node(nid, ino, block, Kind::IndirectNode)?; }
            for addr in freed { self.release_slot(ino, addr)?; }
            return Ok(());
        }
        let child_span = if depth == 1 { d } else { d * p };
        let mut whole: Vec<u32> = Vec::new();
        let mut partial: Vec<(u32, u64)> = Vec::new();
        for i in 0..NIDS_PER_BLOCK {
            let child_base = base + i as u64 * child_span;
            if child_base + child_span <= first_gone { continue; }
            let child = crate::node::indirect_nid(&block, i).unwrap_or(0);
            if child == 0 { continue; }
            if first_gone <= child_base {
                block[i * 4..i * 4 + 4].copy_from_slice(&0u32.to_le_bytes());
                changed = true;
                whole.push(child);
            } else {
                partial.push((child, child_base));
            }
        }
        if changed { self.write_node(nid, ino, block, Kind::IndirectNode)?; }
        for child in whole { self.free_subtree(ino, child, depth - 1)?; }
        for (child, child_base) in partial {
            self.trim_node(ino, child, child_base, first_gone, depth - 1)?;
        }
        Ok(())
    }

    /// Free a node and everything under it.
    ///
    /// `depth` zero is a direct node, whose slots are block addresses; deeper
    /// nodes hold node ids. Freeing a direct node without releasing its
    /// addresses first leaks every block it pointed at.
    /// # C: O(subtree blocks)
    pub(crate) fn free_subtree(&mut self, ino: u32, nid: u32, depth: u8) -> Result<(), Errno> {
        if nid == 0 { return Ok(()); }
        let Ok(node) = self.read_node(nid, Some(ino)) else {
            // A node the table cannot resolve is already gone; dropping its
            // table entry is still right, and is what stops it being handed
            // out as a live id.
            return self.release_node(nid);
        };
        if depth == 0 {
            for i in 0..DEF_ADDRS_PER_BLOCK {
                let addr = crate::node::direct_addr(&node.block, i).unwrap_or(NULL_ADDR);
                self.release_slot(ino, addr)?;
            }
        } else {
            for i in 0..NIDS_PER_BLOCK {
                let child = crate::node::indirect_nid(&node.block, i).unwrap_or(0);
                if child != 0 { self.free_subtree(ino, child, depth - 1)?; }
            }
        }
        self.release_node(nid)?;
        // The node block itself was charged when it was created.
        self.uncharge_space(ino, BLKSIZE as u64)
    }

    /// Free everything an inode owns: its data, its nodes, its attribute
    /// block and finally itself. # C: O(blocks the file has)
    pub(crate) fn free_inode(&mut self, ino: u32) -> Result<(), Errno> {
        // The number is about to be handed to something else, so nothing
        // remembered under it may survive: a run left behind would answer for
        // whatever file next takes the id.
        self.extents.borrow_mut().destroy(ino, 0);
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::EvictInode) {
            return Err(Errno::Eio);
        }
        let inode = self.read_inode(ino)?;
        if !inode.inline_data() && !inode.inline_dentry() {
            let block = self.inode_bytes(ino)?;
            let base = inode.addr_base();
            for i in 0..inode.addrs_per_inode() {
                let addr = le32(&block, base + i * 4).unwrap_or(NULL_ADDR);
                self.release_slot(ino, addr)?;
            }
            for (slot, depth) in [(0usize, 0u8), (1, 0), (2, 1), (3, 1), (4, 2)] {
                let nid = self.inode_slot(ino, slot)?;
                if nid != 0 { self.free_subtree(ino, nid, depth)?; }
            }
        }
        // The attribute node holds attribute bytes, not addresses: walking it
        // as a direct node would release whatever those bytes decode to.
        if inode.xattr_nid != 0 {
            self.release_node(inode.xattr_nid)?;
            self.uncharge_space(ino, BLKSIZE as u64)?;
        }
        // Last: the identity is read off the inode, so it has to still be
        // readable while the rest of its charges are returned. The inode's
        // own block was never charged as space, so only the inode comes back.
        self.uncharge_inode(ino)?;
        self.release_node(ino)?;
        self.valid_inode_count = self.valid_inode_count.saturating_sub(1);
        Ok(())
    }

    /// Every block `ino` occupies: its inode, its nodes and its data.
    ///
    /// Counted off the TREE rather than off the length. A sparse file's length
    /// says nothing about how much of it exists, and counting by index walks
    /// millions of holes to find three blocks.
    /// # C: O(blocks the file has)
    pub(crate) fn count_blocks(&self, ino: u32) -> Result<u64, Errno> {
        let inode = self.read_inode(ino)?;
        // A file whose saved blocks were handed back is no longer charged for
        // the sentinel of each compressed cluster: the slot stays, because it
        // is what says the cluster is an image, and the release gave its
        // charge back with the reservations beside it.
        let released = inode.has(crate::flags::COMPRESS_RELEASED);
        let counts = |addr: u32| addr != NULL_ADDR && !(released && addr == COMPRESS_ADDR);
        let mut n = 1u64;
        // The attribute block is the inode's whether or not its data is
        // inline; counting it only on the non-inline path under-reports every
        // small file that carries attributes.
        if inode.xattr_nid != 0 { n += 1; }
        if inode.inline_data() || inode.inline_dentry() { return Ok(n); }
        let block = self.inode_bytes(ino)?;
        let base = inode.addr_base();
        for i in 0..inode.addrs_per_inode() {
            // A reservation is space the file HOLDS: it names no block on the
            // medium, and the write it is holding room for has one waiting.
            let addr = le32(&block, base + i * 4).unwrap_or(NULL_ADDR);
            if counts(addr) { n += 1; }
        }
        for (slot, depth) in [(0usize, 0u8), (1, 0), (2, 1), (3, 1), (4, 2)] {
            let nid = self.inode_slot(ino, slot)?;
            if nid != 0 { n += self.count_subtree(ino, nid, released, depth)?; }
        }
        Ok(n)
    }

    /// The blocks one node and everything under it occupy. # C: O(subtree)
    fn count_subtree(&self, ino: u32, nid: u32, released: bool, depth: u8) -> Result<u64, Errno> {
        let Ok(node) = self.read_node(nid, Some(ino)) else { return Ok(0) };
        let mut n = 1u64;
        if depth == 0 {
            for i in 0..DEF_ADDRS_PER_BLOCK {
                let addr = crate::node::direct_addr(&node.block, i).unwrap_or(NULL_ADDR);
                if addr != NULL_ADDR && !(released && addr == COMPRESS_ADDR) { n += 1; }
            }
        } else {
            for i in 0..NIDS_PER_BLOCK {
                let child = crate::node::indirect_nid(&node.block, i).unwrap_or(0);
                if child != 0 { n += self.count_subtree(ino, child, released, depth - 1)?; }
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
#[path = "../tests/trim.rs"]
mod tests;
