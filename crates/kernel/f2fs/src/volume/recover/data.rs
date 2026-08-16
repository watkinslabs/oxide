//! Putting the block addresses a recovered node names back into the live
//! file.
//!
//! The recovered block is not adopted. Its ADDRESSES are: for each slot, the
//! address the crashed generation had there (`dest`) replaces the address the
//! checkpoint still records (`src`) in whatever node the live tree uses for
//! that file index. Adopting the block itself would import its node ids too,
//! and those name nodes the checkpoint's table has never heard of.
//!
//! Every slot is one of four cases, and each has to be got right or a block
//! leaks or is shared: the two agree and nothing happens; the recovered slot
//! is empty and the old block is released; the recovered slot is a reservation
//! and the old block is released for one; or the recovered slot names a real
//! block, which is taken from whoever holds it, pointed at, and marked live.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::{DATA_EXIST, INLINE_DATA};
use crate::uapi::*;
use crate::volume::dnode::{put64, Holder};
use crate::volume::fsync::advise;
use crate::volume::Volume;

use super::marks;
use super::scan::Found;

impl<S: SectorSource> Volume<S> {
    /// Restore the inline body a recovered inode carries, and say whether that
    /// settled the file's contents.
    ///
    /// The four combinations of "was inline" and "is inline" are not
    /// symmetric: turning inline OFF must free the blocks the file grew, and
    /// turning it ON must free them too, because the bytes now live inside the
    /// inode and the blocks are unreachable.
    /// # C: O(blocks the file has)
    pub(crate) fn recover_inline_data(&mut self, ino: u32, rec: &[u8]) -> Result<bool, Errno> {
        let inode = self.read_inode(ino)?;
        let rec_inline = rec.get(I_INLINE).map(|b| b & INLINE_DATA != 0).unwrap_or(false);
        if !rec_inline {
            if inode.inline_data() {
                let (at, len) = inode.inline_data_span();
                let mut block = self.inode_bytes(ino)?;
                block[at..at + len].fill(0);
                block[I_INLINE] &= !(INLINE_DATA | DATA_EXIST);
                self.put_inode(ino, block)?;
            }
            return Ok(false);
        }
        if !inode.inline_data() {
            // The BLOCKS go, the length stays. A file whose bytes moved into
            // its inode still has the length the recovered inode records, and
            // it was restored a step ago by the inode pass; shortening the
            // file here would overwrite it with zero and hand the caller an
            // empty file whose bytes are all present and unreachable.
            self.truncate_tail(ino, 0)?;
            let blocks = self.count_blocks(ino)?;
            self.stamp_inode(ino, |b| Self::set_iblocks(b, blocks))?;
            self.refresh_extent(ino)?;
        }
        let inode = self.read_inode(ino)?;
        let (at, len) = inode.inline_data_span();
        if at + len > rec.len() { return Err(Errno::Eio); }
        let body: Vec<u8> = rec[at..at + len].to_vec();
        let mut block = self.inode_bytes(ino)?;
        block[at..at + len].copy_from_slice(&body);
        block[I_INLINE] |= INLINE_DATA | DATA_EXIST;
        self.put_inode(ino, block)?;
        Ok(true)
    }

    /// Point the inode at a recovered attribute node.
    ///
    /// The node block is already on the medium and already correct; what the
    /// checkpoint lacks is a table entry naming it and an inode field pointing
    /// at it, so those are what recovery supplies.
    /// # C: O(1 block)
    pub(crate) fn recover_xattr_node(&mut self, ino: u32, nid: u32, addr: u32)
        -> Result<u32, Errno> {
        self.load_segments()?;
        self.nat_dirty
            .insert(nid, crate::summary::NatEntry { version: 0, ino, block_addr: addr });
        self.update_seg(addr, true)?;
        let old = self.read_inode(ino)?.xattr_nid;
        if old != 0 && old != nid { self.release_node(old)?; }
        let mut block = self.inode_bytes(ino)?;
        block[I_XATTR_NID..I_XATTR_NID + 4].copy_from_slice(&nid.to_le_bytes());
        self.put_inode(ino, block)?;
        Ok(1)
    }

    /// Replay one recovered node's worth of block addresses.
    /// # C: O(addresses in a node) blocks
    pub(crate) fn recover_node_data(&mut self, ino: u32, f: &Found) -> Result<u32, Errno> {
        let rec = self.read_main_block(f.addr)?;
        if f.ofs == marks::xattr_node_offset() {
            return self.recover_xattr_node(ino, f.nid, f.addr);
        }
        if f.is_inode && self.recover_inline_data(ino, &rec)? { return Ok(1); }
        let inode = self.read_inode(ino)?;
        let apb = inode.addrs_per_inode();
        let start = marks::start_bidx_of_node(f.ofs, apb);
        let count = marks::addrs_per_page(f.is_inode, apb);
        if start >= crate::node::path::max_block(apb) { return Err(Errno::Eio); }
        let (holder, base) = self.dnode_for_write(ino, start)?;
        let keep_nid = match holder { Holder::Inode => ino, Holder::Direct(nid) => nid };
        // The holder is read ONCE and written ONCE. Going through the
        // per-slot setter instead would rewrite the node out of place for
        // every address in it — a thousand blocks out of the log to replay
        // one node, which exhausts a segment long before the chain ends.
        let (mut hblock, hbase) = match holder {
            Holder::Inode => (self.inode_bytes(ino)?, inode.addr_base()),
            Holder::Direct(nid) => (self.read_node(nid, Some(ino))?.block, 0usize),
        };
        let mut recovered = 0u32;
        let mut grown = inode.size;
        let keep_size = advise::keep_isize(inode.advise);
        let mut freed: Vec<u32> = Vec::new();
        for i in 0..count {
            let dest = self.recovered_addr(&inode, &rec, f.is_inode, i)?;
            let at = hbase + (base + i) * 4;
            if at + 4 > NODE_FOOTER_OFF { break; }
            let src = le32(&hblock, at).unwrap_or(NULL_ADDR);
            if src == dest { continue; }
            if !crate::node::is_hole(dest) {
                self.drop_previous_owner(dest, keep_nid)?;
                self.update_seg(dest, true)?;
                let end = (start + i as u64 + 1) << BLKSIZE_BITS;
                if !keep_size && grown < end { grown = end; }
                recovered += 1;
            }
            // A reservation (`NEW_ADDR`) is carried through as it stands: it
            // names no block, so it marks nothing live and grows no size, and
            // it reads as a hole until a write allocates over it. It still
            // COSTS a block, because the write it is holding room for has to
            // find one, so it is charged the moment it is installed and given
            // back the moment the slot stops holding it — the two together are
            // what keep the count from drifting either way.
            if dest == NEW_ADDR { self.charge_reservation(); }
            if src == NEW_ADDR { self.release_reservation(); }
            // A block the crashed generation left behind becomes this file's
            // from here on, so its owner is charged for it — nothing else on
            // the replay path does. The charge can be REFUSED, and that
            // refusal fails the replay and with it the mount: adopting blocks
            // an identity may not have would put the volume back with an
            // overdraft nobody ever agreed to.
            if !crate::node::is_hole(dest) && crate::node::is_hole(src) {
                self.charge_space(ino, BLKSIZE as u64)?;
            }
            if crate::node::is_hole(dest) && !crate::node::is_hole(src) {
                self.uncharge_space(ino, BLKSIZE as u64)?;
            }
            hblock[at..at + 4].copy_from_slice(&dest.to_le_bytes());
            if !crate::node::is_hole(src) { freed.push(src); }
        }
        match holder {
            Holder::Inode => {
                if grown != inode.size { put64(&mut hblock, I_SIZE, grown); }
                self.put_inode(ino, hblock)?;
            }
            Holder::Direct(nid) => {
                let kind = self.node_kind(inode.mode);
                self.write_node(nid, ino, hblock, kind)?;
                if grown != inode.size { self.stamp_inode(ino, |b| put64(b, I_SIZE, grown))?; }
            }
        }
        self.refresh_extent(ino)?;
        // The count the file reports has to move with the blocks it just
        // gained or lost. A checker compares it against what the tree holds,
        // and a replay that changed the tree without it leaves every recovered
        // file reporting the shape it had before the crash.
        let blocks = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| Self::set_iblocks(b, blocks))?;
        for addr in freed { self.release_block(addr)?; }
        Ok(recovered)
    }

    /// Count a reservation against the volume.
    ///
    /// A reservation occupies no block of the medium and so sets no bit in the
    /// segment table, which is why this cannot go through the segment update:
    /// the count and the table deliberately disagree by exactly the number of
    /// reservations outstanding.
    /// # C: O(1)
    pub(crate) fn charge_reservation(&mut self) { self.valid_block_count += 1; }

    /// Give a reservation's charge back, when the slot holding it stops
    /// holding it. # C: O(1)
    pub(crate) fn release_reservation(&mut self) {
        self.valid_block_count = self.valid_block_count.saturating_sub(1);
    }

    /// One address out of the recovered block, in the shape that block has.
    /// # C: O(1)
    fn recovered_addr(&self, inode: &crate::node::Inode, rec: &[u8], is_inode: bool, i: usize)
        -> Result<u32, Errno> {
        let a = if is_inode {
            inode.addr(rec, i).unwrap_or(NULL_ADDR)
        } else {
            crate::node::direct_addr(rec, i).unwrap_or(NULL_ADDR)
        };
        if !crate::node::is_hole(a) && !self.sb.valid_main_blkaddr(a) { return Err(Errno::Eio); }
        Ok(a)
    }
}

#[cfg(test)]
#[path = "../../tests/recover/reserve.rs"]
mod tests;
