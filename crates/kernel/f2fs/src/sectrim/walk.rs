//! The last block index a file has anything at.
//!
//! A request may name "everything to the end", and the end it means is the
//! volume's largest offset rather than the file's length — a file can hold
//! blocks past what its length admits to. Walking that whole index space one
//! block at a time would be a walk of billions for a file of three, so the
//! walk is over the TREE, which has one entry per block that exists.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// The highest block index `ino` holds anything at, or `None` when it
    /// holds nothing. # C: O(nodes the file has) blocks
    pub(crate) fn highest_block_index(&self, ino: u32) -> Result<Option<u64>, Errno> {
        let inode = self.read_inode(ino)?;
        if inode.inline_data() || inode.inline_dentry() { return Ok(None); }
        let apb = inode.addrs_per_inode() as u64;
        let d = DEF_ADDRS_PER_BLOCK as u64;
        let p = NIDS_PER_BLOCK as u64;
        let bases = [apb, apb + d, apb + 2 * d, apb + 2 * d + d * p, apb + 2 * d + 2 * d * p];
        // Deepest slot first: anything it holds is past everything shallower.
        for (slot, depth) in [(4usize, 2u8), (3, 1), (2, 1), (1, 0), (0, 0)] {
            let nid = self.inode_slot(ino, slot)?;
            if nid == 0 { continue; }
            if let Some(i) = self.max_in_subtree(ino, nid, bases[slot], depth)? {
                return Ok(Some(i));
            }
        }
        let block = self.inode_bytes(ino)?;
        let base = inode.addr_base();
        for i in (0..inode.addrs_per_inode()).rev() {
            if le32(&block, base + i * 4).unwrap_or(NULL_ADDR) != NULL_ADDR {
                return Ok(Some(i as u64));
            }
        }
        Ok(None)
    }

    /// The highest index anything under one node covers.
    /// # C: O(subtree) blocks
    fn max_in_subtree(&self, ino: u32, nid: u32, base: u64, depth: u8)
        -> Result<Option<u64>, Errno> {
        let Ok(node) = self.read_node(nid, Some(ino)) else { return Ok(None) };
        let d = DEF_ADDRS_PER_BLOCK as u64;
        let p = NIDS_PER_BLOCK as u64;
        if depth == 0 {
            for i in (0..DEF_ADDRS_PER_BLOCK).rev() {
                if crate::node::direct_addr(&node.block, i).unwrap_or(NULL_ADDR) != NULL_ADDR {
                    return Ok(Some(base + i as u64));
                }
            }
            return Ok(None);
        }
        let span = if depth == 1 { d } else { d * p };
        for i in (0..NIDS_PER_BLOCK).rev() {
            let child = crate::node::indirect_nid(&node.block, i).unwrap_or(0);
            if child == 0 { continue; }
            let at = base + i as u64 * span;
            if let Some(x) = self.max_in_subtree(ino, child, at, depth - 1)? {
                return Ok(Some(x));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
#[path = "../tests/sectrim/walk.rs"]
mod tests;
