//! A node id into a node block, and an inode out of one.
//!
//! Three checks stand between a node id and a usable block, and each one
//! catches a failure that would otherwise be silent:
//!
//! - The **journal** may hold a fresher address than the table.
//! - The address must lie in the MAIN area, or it names metadata.
//! - The block's own footer must name the node that was asked for, or the
//!   table has drifted and the block belongs to something else.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::nat;
use crate::node::{self, footer, Inode};
use crate::uapi::*;

use super::Volume;

/// A node block and the footer that identifies it.
pub struct NodeRef {
    pub block: Vec<u8>,
    pub footer: footer::Footer,
}

impl<S: SectorSource> Volume<S> {
    /// The block address the node table currently gives for `nid`.
    /// # C: O(journal entries + 1 block)
    pub fn node_addr(&self, nid: u32) -> Result<u32, Errno> {
        let max = nat::max_nid(self.sb.segment_count_nat, self.sb.blks_per_seg());
        if !nat::nid_in_range(nid, max) { return Err(Errno::Einval); }
        // The journal is consulted through `resolve`, which reads the table
        // block only when the journal has nothing — but the block address is
        // needed either way, so it is computed first.
        let addr = nat::block_addr(
            self.sb.nat_blkaddr,
            self.sb.blks_per_seg(),
            nid,
            &self.nat_bitmap,
        );
        // The dirty set first: an address this mount has just written is not
        // on the medium yet, and the table still names the block it replaced.
        if let Some(e) = self.nat_dirty.get(&nid) { return Ok(e.block_addr); }
        if let Some(e) = nat::journalled(&self.nat_journal, nid) { return Ok(e.block_addr); }
        let block = self.read_block(addr)?;
        let entry = nat::resolve(&self.nat_journal, &block, nid).ok_or(Errno::Eio)?;
        Ok(entry.block_addr)
    }

    /// The node block for `nid`, with its footer checked.
    ///
    /// `ino` is passed when the caller knows which file the node must belong
    /// to; an inode's own read passes `None` because the footer is what states
    /// the inode number in the first place.
    /// # C: O(1 block)
    pub fn read_node(&self, nid: u32, ino: Option<u32>) -> Result<NodeRef, Errno> {
        let addr = self.node_addr(nid)?;
        if node::is_hole(addr) { return Err(Errno::Enoent); }
        let block = self.read_main_block(addr)?;
        let f = footer::expect(&block, nid, ino).map_err(|_| Errno::Eio)?;
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::InconsistentFooter) {
            return Err(Errno::Eio);
        }
        Ok(NodeRef { block, footer: f })
    }

    /// The inode numbered `ino`.
    ///
    /// The checksum is verified here rather than at the caller because an
    /// inode that fails it must not be handed out at all: its size, its inline
    /// flags and its address array are all read from the same bytes.
    /// # C: O(1 block)
    pub fn read_inode_ref(&self, ino: u32) -> Result<(Inode, NodeRef), Errno> {
        let n = self.read_node(ino, Some(ino))?;
        if !n.footer.is_inode() { return Err(Errno::Eio); }
        let inode = node::inode::parse(&n.block, self.sb.feature).ok_or(Errno::Eio)?;
        node::inode::sanity(&inode, ino, self.sb.feature).map_err(|_| Errno::Eio)?;
        if !node::inode::checksum_ok(&inode, &n.block, self.inode_seed, self.sb.feature) {
            return Err(Errno::Eio);
        }
        Ok((inode, n))
    }

    /// The inode numbered `ino`, without its block. # C: O(1 block)
    pub fn read_inode(&self, ino: u32) -> Result<Inode, Errno> {
        Ok(self.read_inode_ref(ino)?.0)
    }

    /// One address out of a direct node, or out of the inode itself.
    ///
    /// The inode's array is offset by its extra attributes, and a direct
    /// node's is not, so which of the two a block is decides where slot zero
    /// begins.
    /// # C: O(1)
    pub fn addr_at(&self, inode: &Inode, n: &NodeRef, index: usize) -> Option<u32> {
        if n.footer.is_inode() { inode.addr(&n.block, index) } else { node::direct_addr(&n.block, index) }
    }

    /// How many node ids the table can name. # C: O(1)
    pub fn max_nid(&self) -> u32 {
        nat::max_nid(self.sb.segment_count_nat, self.sb.blks_per_seg())
    }

    /// The attribute node of an inode, when it has one. # C: O(1 block)
    pub fn read_xattr_node(&self, inode: &Inode, ino: u32) -> Result<Option<Vec<u8>>, Errno> {
        if inode.xattr_nid == NULL_ADDR { return Ok(None); }
        let n = self.read_node(inode.xattr_nid, Some(ino))?;
        Ok(Some(n.block))
    }
}
