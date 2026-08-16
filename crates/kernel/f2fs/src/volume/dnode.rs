//! Reaching — and creating — the node that holds a file block's address.
//!
//! A read stops at the first missing link and calls the block a hole. A WRITE
//! cannot: it has to build the missing links, and each one it builds is
//! another node whose own address has to be recorded, and whose parent has to
//! be rewritten to point at it. Every one of those rewrites is out of place,
//! so creating one block deep in a large file moves four node blocks.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::mode;
use crate::node::{path, Step};
use crate::uapi::*;

use super::curseg::Kind;
use super::Volume;

/// Stamp a node block's own offset within its inode's node tree.
///
/// `write_node` deliberately leaves the flag word alone, so this is set by the
/// caller that knows where in the tree the node sits — and it must be, because
/// a node whose recorded offset is zero claims to BE the inode. The low mark
/// bits are preserved: they carry the cold, fsync and dentry marks.
/// # C: O(1)
pub fn set_node_ofs(block: &mut [u8], ofs: u32) {
    let at = NODE_FOOTER_OFF + FOOTER_FLAG;
    let old = le32(block, at).unwrap_or(0);
    let flag = (ofs << crate::flags::OFFSET_BIT_SHIFT) | (old & crate::flags::OFFSET_BIT_MASK);
    block[at..at + 4].copy_from_slice(&flag.to_le_bytes());
}

/// Where each of the inode's five node slots sits in the tree. # C: O(1)
pub fn slot_ofs(slot: usize) -> u32 {
    let p = NIDS_PER_BLOCK as u32;
    match slot {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 4 + p,
        _ => 5 + 2 * p,
    }
}

/// Which node carries a file block's address.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Holder {
    /// The inode's own array.
    Inode,
    /// A direct node.
    Direct(u32),
}

impl<S: SectorSource> Volume<S> {
    /// The kind of log an inode's own node blocks belong in. # C: O(1)
    pub(crate) fn node_kind(&self, mode_word: u16) -> Kind {
        if mode::file_type(mode_word) == vfs::FileType::Directory { Kind::DirNode }
        else { Kind::FileNode }
    }

    /// An inode's block, as stored. # C: O(1 block)
    pub(crate) fn inode_bytes(&self, ino: u32) -> Result<Vec<u8>, Errno> {
        Ok(self.read_inode_ref(ino)?.1.block)
    }

    /// Write an inode block back, out of place. # C: O(BLKSIZE)
    pub(crate) fn put_inode(&mut self, ino: u32, block: Vec<u8>) -> Result<(), Errno> {
        let mode_word = le16(&block, I_MODE).ok_or(Errno::Eio)?;
        let kind = self.node_kind(mode_word);
        self.write_node(ino, ino, block, kind)?;
        Ok(())
    }

    /// The node that holds block `index` of `ino`, creating what is missing.
    /// # C: O(indirection depth) blocks
    pub(crate) fn dnode_for_write(&mut self, ino: u32, index: u64)
        -> Result<(Holder, usize), Errno> {
        let inode = self.read_inode(ino)?;
        let kind = self.node_kind(inode.mode);
        let p = path::node_path(inode.addrs_per_inode(), index).ok_or(Errno::Efbig)?;
        match p.step() {
            Step::InInode { index } => Ok((Holder::Inode, index)),
            Step::Direct { nid_slot, index } => {
                let nid = self.ensure_inode_nid(ino, nid_slot, kind)?;
                Ok((Holder::Direct(nid), index))
            }
            Step::Indirect { nid_slot, dnode, index } => {
                let ind = self.ensure_inode_nid(ino, nid_slot, Kind::IndirectNode)?;
                let d = self.ensure_child_nid(ind, ino, dnode, kind)?;
                Ok((Holder::Direct(d), index))
            }
            Step::DoubleIndirect { nid_slot, indirect, dnode, index } => {
                let outer = self.ensure_inode_nid(ino, nid_slot, Kind::IndirectNode)?;
                // Each middle node costs its own block plus a block of leaves.
                let stride = NIDS_PER_BLOCK as u32 + 1;
                let mid =
                    self.ensure_child_nid_at(outer, ino, indirect, Kind::IndirectNode, stride)?;
                let d = self.ensure_child_nid(mid, ino, dnode, kind)?;
                Ok((Holder::Direct(d), index))
            }
        }
    }

    /// The node one of the inode's five slots names, created if empty.
    /// # C: O(1) blocks
    pub(crate) fn ensure_inode_nid(&mut self, ino: u32, slot: usize, kind: Kind)
        -> Result<u32, Errno> {
        let mut block = self.inode_bytes(ino)?;
        let at = I_NID_OFF + slot * 4;
        let existing = le32(&block, at).ok_or(Errno::Eio)?;
        if existing != 0 { return Ok(existing); }
        let nid = self.alloc_nid()?;
        let mut fresh = vec![0u8; BLKSIZE];
        set_node_ofs(&mut fresh, slot_ofs(slot));
        self.write_node(nid, ino, fresh, kind)?;
        block[at..at + 4].copy_from_slice(&nid.to_le_bytes());
        self.put_inode(ino, block)?;
        Ok(nid)
    }

    /// The node one slot of another node names, created if empty.
    /// # C: O(1) blocks
    pub(crate) fn ensure_child_nid(&mut self, parent: u32, ino: u32, slot: usize, kind: Kind)
        -> Result<u32, Errno> {
        self.ensure_child_nid_at(parent, ino, slot, kind, 1)
    }

    /// The same, saying how many tree offsets each child of `parent` spans.
    ///
    /// A leaf under an indirect node spans one; a middle node under a
    /// double-indirect spans its own block plus a block of leaves, so the
    /// offsets step by more than one and a node stamped with the wrong one
    /// claims to be a different node of the same file.
    /// # C: O(1) blocks
    pub(crate) fn ensure_child_nid_at(&mut self, parent: u32, ino: u32, slot: usize, kind: Kind,
                                      stride: u32) -> Result<u32, Errno> {
        let mut block = self.read_node(parent, Some(ino))?.block;
        let at = slot * 4;
        let existing = le32(&block, at).ok_or(Errno::Eio)?;
        if existing != 0 { return Ok(existing); }
        let parent_ofs = crate::node::footer::parse(&block).map(|f| f.ofs_of_node()).unwrap_or(0);
        let nid = self.alloc_nid()?;
        let mut fresh = vec![0u8; BLKSIZE];
        set_node_ofs(&mut fresh, parent_ofs + 1 + slot as u32 * stride);
        self.write_node(nid, ino, fresh, kind)?;
        block[at..at + 4].copy_from_slice(&nid.to_le_bytes());
        self.write_node(parent, ino, block, Kind::IndirectNode)?;
        Ok(nid)
    }

    /// The address currently recorded at `(holder, ofs)`. # C: O(1 block)
    pub(crate) fn holder_addr(&self, ino: u32, holder: Holder, ofs: usize)
        -> Result<u32, Errno> {
        match holder {
            Holder::Inode => {
                let (inode, node) = self.read_inode_ref(ino)?;
                Ok(inode.addr(&node.block, ofs).unwrap_or(NULL_ADDR))
            }
            Holder::Direct(nid) => {
                let n = self.read_node(nid, Some(ino))?;
                Ok(crate::node::direct_addr(&n.block, ofs).unwrap_or(NULL_ADDR))
            }
        }
    }

    /// Record `addr` at `(holder, ofs)`, rewriting the node that holds it.
    /// # C: O(1 block)
    pub(crate) fn set_holder_addr(&mut self, ino: u32, holder: Holder, ofs: usize, addr: u32)
        -> Result<(), Errno> {
        match holder {
            Holder::Inode => {
                let inode = self.read_inode(ino)?;
                let mut block = self.inode_bytes(ino)?;
                if ofs >= inode.addrs_per_inode() { return Err(Errno::Efbig); }
                let at = inode.addr_base() + ofs * 4;
                block[at..at + 4].copy_from_slice(&addr.to_le_bytes());
                self.put_inode(ino, block)?;
                // The cached extent is computed from exactly these addresses,
                // and a write moves blocks. Left alone it keeps answering
                // with the address the block used to have, and every read of
                // that block returns the PREVIOUS contents — stale data, with
                // nothing reporting an error. Only the inode's own array
                // feeds the extent, so a direct node's addresses cannot
                // invalidate it.
                self.refresh_extent(ino)
            }
            Holder::Direct(nid) => {
                let mut block = self.read_node(nid, Some(ino))?.block;
                if ofs >= DEF_ADDRS_PER_BLOCK { return Err(Errno::Efbig); }
                let at = ofs * 4;
                block[at..at + 4].copy_from_slice(&addr.to_le_bytes());
                let inode = self.read_inode(ino)?;
                let kind = self.node_kind(inode.mode);
                self.write_node(nid, ino, block, kind)?;
                Ok(())
            }
        }
    }

    /// Read one of the inode's five node slots. # C: O(1 block)
    pub(crate) fn inode_slot(&self, ino: u32, slot: usize) -> Result<u32, Errno> {
        let block = self.inode_bytes(ino)?;
        le32(&block, I_NID_OFF + slot * 4).ok_or(Errno::Eio)
    }

    /// Clear one of the inode's five node slots. # C: O(1 block)
    pub(crate) fn clear_inode_slot(&mut self, ino: u32, slot: usize) -> Result<(), Errno> {
        let mut block = self.inode_bytes(ino)?;
        let at = I_NID_OFF + slot * 4;
        block[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
        self.put_inode(ino, block)
    }

    /// Update the inode's own bookkeeping fields in one rewrite.
    ///
    /// Doing these one at a time would rewrite the inode block once per field,
    /// and every rewrite costs a fresh block out of the log.
    /// # C: O(1 block)
    pub(crate) fn stamp_inode(&mut self, ino: u32, f: impl FnOnce(&mut Vec<u8>))
        -> Result<(), Errno> {
        let mut block = self.inode_bytes(ino)?;
        f(&mut block);
        self.put_inode(ino, block)
    }

    /// Count the blocks a file occupies, its own inode block included, and
    /// record it. The stored count is what a checker compares against the
    /// segment table. # C: O(1)
    pub(crate) fn set_iblocks(block: &mut [u8], blocks: u64) {
        block[I_BLOCKS..I_BLOCKS + 8].copy_from_slice(&blocks.max(1).to_le_bytes());
    }
}

/// Write a little-endian value into an inode or node block. # C: O(1)
pub fn put16(b: &mut [u8], at: usize, v: u16) { b[at..at + 2].copy_from_slice(&v.to_le_bytes()); }
/// # C: O(1)
pub fn put32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
/// # C: O(1)
pub fn put64(b: &mut [u8], at: usize, v: u64) { b[at..at + 8].copy_from_slice(&v.to_le_bytes()); }
