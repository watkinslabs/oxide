//! A file's block index into the block address that holds it.
//!
//! The walk stops at the first missing link and reports a HOLE, not an error.
//! A file may be sparse at any level: an unallocated indirect node means every
//! block it would have covered is a hole, and treating that as corruption
//! makes a legitimately sparse file unreadable.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::{self, path, Inode, Step};

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
                let Some(nid) = self.inode_nid(ino, nid_slot)? else { return Ok(Mapped::Hole) };
                let n = self.read_node(nid, Some(ino))?;
                node::direct_addr(&n.block, index)
            }
            Step::Indirect { nid_slot, dnode, index } => {
                let Some(nid) = self.inode_nid(ino, nid_slot)? else { return Ok(Mapped::Hole) };
                let ind = self.read_node(nid, Some(ino))?;
                let Some(dnid) = live_nid(node::indirect_nid(&ind.block, dnode))
                    else { return Ok(Mapped::Hole) };
                let d = self.read_node(dnid, Some(ino))?;
                node::direct_addr(&d.block, index)
            }
            Step::DoubleIndirect { nid_slot, indirect, dnode, index } => {
                let Some(nid) = self.inode_nid(ino, nid_slot)? else { return Ok(Mapped::Hole) };
                let outer = self.read_node(nid, Some(ino))?;
                let Some(mid_nid) = live_nid(node::indirect_nid(&outer.block, indirect))
                    else { return Ok(Mapped::Hole) };
                let mid = self.read_node(mid_nid, Some(ino))?;
                let Some(dnid) = live_nid(node::indirect_nid(&mid.block, dnode))
                    else { return Ok(Mapped::Hole) };
                let d = self.read_node(dnid, Some(ino))?;
                node::direct_addr(&d.block, index)
            }
        };
        let Some(addr) = addr else { return Ok(Mapped::Hole) };
        if node::is_compressed(addr) { return Ok(Mapped::Compressed); }
        if node::is_hole(addr) { return Ok(Mapped::Hole); }
        if !self.sb.valid_main_blkaddr(addr) { return Err(Errno::Eio); }
        Ok(Mapped::At(addr))
    }

    /// One of the inode's five node ids, or `None` when the slot is empty.
    /// # C: O(1 block)
    fn inode_nid(&self, ino: u32, slot: usize) -> Result<Option<u32>, Errno> {
        let (inode, n) = self.read_inode_ref(ino)?;
        let _ = &inode;
        Ok(live_nid(crate::uapi::le32(&n.block, crate::uapi::I_NID_OFF + slot * 4)))
    }
}

/// A node id that names something, or `None` for the empty slot. # C: O(1)
fn live_nid(nid: Option<u32>) -> Option<u32> {
    match nid { Some(0) | None => None, Some(n) => Some(n) }
}
