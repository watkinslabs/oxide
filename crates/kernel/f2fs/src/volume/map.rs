//! A file's block index into the block address that holds it.
//!
//! The walk stops at the first missing link and reports a HOLE, not an error.
//! A file may be sparse at any level: an unallocated indirect node means every
//! block it would have covered is a hole, and treating that as corruption
//! makes a legitimately sparse file unreadable.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::{self, path, Inode, Step};
use crate::uapi::NULL_ADDR;

use super::Volume;

/// Where a file's block lives.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mapped {
    /// The block is at this address in the main area.
    At(u32),
    /// Nothing is allocated; the block reads as zeroes.
    Hole,
    /// The block heads a compressed cluster, which this build does not
    /// decompress.
    Compressed,
}

impl<S: SectorSource> Volume<S> {
    /// The address of block `index` of the file `inode`.
    ///
    /// `ino` is the inode's own number, checked against every node the walk
    /// passes through: a direct node reached from the right inode but carrying
    /// another file's number is a table that has drifted.
    /// # C: O(indirection depth) blocks
    pub fn map_block(&self, inode: &Inode, ino: u32, index: u64) -> Result<Mapped, Errno> {
        // The inode caches one extent. Consulting it saves the walk for the
        // contiguous run most files are, and it is only consulted after it is
        // checked against the main area — a stale one would otherwise hand
        // back another file's blocks.
        if let Some(addr) = inode.extent_addr(index) {
            if self.extent_is_sane(inode) { return Ok(Mapped::At(addr)); }
        }
        let Some(addr) = self.map_block_raw(inode, ino, index)? else { return Ok(Mapped::Hole) };
        if node::is_compressed(addr) { return Ok(Mapped::Compressed); }
        if node::is_hole(addr) { return Ok(Mapped::Hole); }
        if !self.sb.valid_main_blkaddr(addr) { return Err(Errno::Eio); }
        Ok(Mapped::At(addr))
    }

    /// The address the node tree stores for `index`, with no interpretation.
    ///
    /// `None` means a link on the way was absent, so nothing is stored at all.
    /// # C: O(indirection depth) blocks
    pub(crate) fn map_block_raw(&self, inode: &Inode, ino: u32, index: u64)
        -> Result<Option<u32>, Errno> {
        let p = match path::node_path(inode.addrs_per_inode(), index) {
            Some(p) => p,
            None => return Err(Errno::Efbig),
        };
        let addr = match p.step() {
            Step::InInode { index } => {
                let n = self.read_inode_ref(ino)?.1;
                inode.addr(&n.block, index)
            }
            Step::Direct { nid_slot, index } => {
                let Some(nid) = self.inode_nid(ino, nid_slot)? else { return Ok(None) };
                let n = self.read_node(nid, Some(ino))?;
                node::direct_addr(&n.block, index)
            }
            Step::Indirect { nid_slot, dnode, index } => {
                let Some(nid) = self.inode_nid(ino, nid_slot)? else { return Ok(None) };
                let ind = self.read_node(nid, Some(ino))?;
                let Some(dnid) = live_nid(node::indirect_nid(&ind.block, dnode))
                    else { return Ok(None) };
                let d = self.read_node(dnid, Some(ino))?;
                node::direct_addr(&d.block, index)
            }
            Step::DoubleIndirect { nid_slot, indirect, dnode, index } => {
                let Some(nid) = self.inode_nid(ino, nid_slot)? else { return Ok(None) };
                let outer = self.read_node(nid, Some(ino))?;
                let Some(mid_nid) = live_nid(node::indirect_nid(&outer.block, indirect))
                    else { return Ok(None) };
                let mid = self.read_node(mid_nid, Some(ino))?;
                let Some(dnid) = live_nid(node::indirect_nid(&mid.block, dnode))
                    else { return Ok(None) };
                let d = self.read_node(dnid, Some(ino))?;
                node::direct_addr(&d.block, index)
            }
        };
        Ok(addr)
    }

    /// The address STORED for `index`, uninterpreted.
    ///
    /// `map_block` turns the two hole spellings and the compressed sentinel
    /// into an answer; a cluster walk needs the sentinel itself, because it is
    /// what marks the head of the run.
    /// # C: O(indirection depth) blocks
    pub(crate) fn stored_addr(&self, inode: &Inode, ino: u32, index: u64)
        -> Result<u32, Errno> {
        match self.map_block_raw(inode, ino, index)? {
            Some(addr) => Ok(addr),
            None => Ok(NULL_ADDR),
        }
    }

    /// One of the inode's five node ids, or `None` when the slot is empty.
    /// # C: O(1 block)
    fn inode_nid(&self, ino: u32, slot: usize) -> Result<Option<u32>, Errno> {
        let (inode, n) = self.read_inode_ref(ino)?;
        let _ = &inode;
        Ok(live_nid(crate::uapi::le32(&n.block, crate::uapi::I_NID_OFF + slot * 4)))
    }
}

impl<S: SectorSource> Volume<S> {
    /// Whether the inode's cached extent can describe real blocks.
    ///
    /// Both ends are checked, not just the start: an extent whose length runs
    /// off the end of the main area would answer for indexes it cannot cover.
    /// # C: O(1)
    pub fn extent_is_sane(&self, inode: &Inode) -> bool {
        match inode.cached_extent() {
            None => false,
            Some((_, blk, len)) => {
                self.sb.valid_main_blkaddr(blk) && self.sb.valid_main_blkaddr(blk + len - 1)
            }
        }
    }
}

/// A node id that names something, or `None` for the empty slot. # C: O(1)
fn live_nid(nid: Option<u32>) -> Option<u32> {
    match nid { Some(0) | None => None, Some(n) => Some(n) }
}

impl<S: SectorSource> Volume<S> {
    /// Recompute the inode's cached extent from what it now holds.
    ///
    /// The run recorded is the longest contiguous one starting at file offset
    /// zero, inside the inode's own address array — the shape almost every
    /// small file has, and the one a read benefits from most. Anything the run
    /// does not cover falls through to the node walk, so a short answer costs
    /// a walk and never a wrong block.
    ///
    /// Recomputing beats patching: a write moves blocks, and an extent
    /// repaired in place is one that is sometimes wrong, which is worse than
    /// no cache at all.
    /// # C: O(addresses in the inode)
    pub(crate) fn refresh_extent(&mut self, ino: u32) -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        if inode.inline_data() || inode.inline_dentry() { return self.clear_extent(ino); }
        let block = self.inode_bytes(ino)?;
        let base = inode.addr_base();
        let first = crate::uapi::le32(&block, base).unwrap_or(NULL_ADDR);
        if crate::node::is_hole(first) || !self.sb.valid_main_blkaddr(first) {
            return self.clear_extent(ino);
        }
        let mut len = 1u32;
        while (len as usize) < inode.addrs_per_inode() {
            let at = base + len as usize * 4;
            let addr = crate::uapi::le32(&block, at).unwrap_or(NULL_ADDR);
            if addr != first.wrapping_add(len) || !self.sb.valid_main_blkaddr(addr) { break; }
            len += 1;
        }
        if inode.ext == (0, first, len) { return Ok(()); }
        self.stamp_inode(ino, |b| {
            let put = |b: &mut [u8], at: usize, v: u32| {
                b[at..at + 4].copy_from_slice(&v.to_le_bytes())
            };
            put(b, crate::uapi::I_EXT_FOFS, 0);
            put(b, crate::uapi::I_EXT_BLK, first);
            put(b, crate::uapi::I_EXT_LEN, len);
        })
    }

    /// Forget the cached extent. # C: O(1 block)
    pub(crate) fn clear_extent(&mut self, ino: u32) -> Result<(), Errno> {
        if self.read_inode(ino)?.ext.2 == 0 { return Ok(()); }
        self.stamp_inode(ino, |b| {
            b[crate::uapi::I_EXT_LEN..crate::uapi::I_EXT_LEN + 4]
                .copy_from_slice(&0u32.to_le_bytes());
        })
    }
}

#[cfg(test)]
#[path = "../tests/extent.rs"]
mod tests;
