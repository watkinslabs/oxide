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
        // The node mapping FIRST. A node changed since the last flush has not
        // been placed and the table gives it no address, so a read that went
        // to the table would answer with the node's previous contents — or,
        // for a node created since, with nothing at all.
        if let Some(block) = self.peek_node(nid) {
            let f = self.footer_or_note(&block, nid, ino)?;
            if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::InconsistentFooter) {
                self.note_error(crate::errrec::Error::InconsistentFooter);
                return Err(Errno::Eio);
            }
            return Ok(NodeRef { block, footer: f });
        }
        self.node_cache.miss();
        let addr = self.node_addr(nid)?;
        if node::is_hole(addr) { return Err(Errno::Enoent); }
        let block = self.read_main_block(addr)?;
        self.io_account(crate::stats::iostat::Io::FsNodeRead, crate::uapi::BLKSIZE as u64, false);
        let f = self.footer_or_note(&block, nid, ino)?;
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::InconsistentFooter) {
            self.note_error(crate::errrec::Error::InconsistentFooter);
            return Err(Errno::Eio);
        }
        // Kept CLEAN, so the next read of the same node costs nothing. Nothing
        // changes a node behind this mapping: every writer of a node block in
        // this filesystem files its result here on the way past.
        self.node_cache.fill(nid, block.clone());
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
        // Every arm below is one kind: bytes that claim to be this inode and
        // are not usable as one. Recorded so the volume reaches the next mount
        // and fsck saying an inode is damaged, rather than only answering EIO
        // to whoever happened to open it.
        let corrupt = || { self.note_error(crate::errrec::Error::CorruptedInode); Errno::Eio };
        if !n.footer.is_inode() { return Err(corrupt()); }
        let inode = node::inode::parse(&n.block, self.sb.feature).ok_or_else(corrupt)?;
        node::inode::sanity(&inode, ino, self.sb.feature).map_err(|_| corrupt())?;
        if !node::inode::checksum_ok(&inode, &n.block, self.inode_seed, self.sb.feature) {
            return Err(corrupt());
        }
        // A file that stands for a member device must stand for a REAL one.
        // The flag's agreement with the volume's features and the file's
        // pinning is settled by `sanity`, which sees neither the member table
        // nor the zone reports; the extent's agreement with a member's span is
        // settled here, where both are reachable. An extent matching no
        // member, or member zero, or a zoned member, describes blocks that are
        // not a device to hand out — and handing them out would give one span
        // two owners.
        if crate::devices::alias::is_alias(inode.flags) && self.alias_device(&inode).is_err() {
            return Err(corrupt());
        }
        Ok((inode, n))
    }

    /// The footer of a node block, recording a mismatch before reporting it.
    ///
    /// A footer that names a different node or a different owner means the
    /// table pointed here wrongly or the block was overwritten; either way the
    /// disagreement is between two structures and belongs on the medium.
    /// # C: O(1)
    fn footer_or_note(&self, block: &[u8], nid: u32, ino: Option<u32>)
        -> Result<footer::Footer, Errno> {
        footer::expect(block, nid, ino).map_err(|_| {
            self.note_error(crate::errrec::Error::InconsistentFooter);
            Errno::Eio
        })
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
