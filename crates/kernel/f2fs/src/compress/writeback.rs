//! Writing a compressed file: one whole cluster at a time.
//!
//! A block of a compressed file cannot be written by itself. The cluster it
//! belongs to is one image, so changing a byte means reading the cluster back,
//! putting the byte in, and writing the whole cluster again — the read is not
//! an optimisation, it is the only way to know what the other blocks held.
//!
//! Two rules decide whether the cluster comes out compressed at all, and
//! getting either wrong is silent:
//!
//! - A cluster the file's SIZE stops part way through is stored plain. Its
//!   tail blocks are past the end of the file, and an image covering them
//!   would be rewritten by the next append.
//! - A cluster whose image does not save a whole block is stored plain. The
//!   format measures the saving in blocks, so an image that still needs all of
//!   them has cost a decompression per read and saved nothing.
//!
//! The slots the image does not need are RESERVED, not cleared: see `plan`.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::Inode;
use crate::uapi::{le64, BLKSIZE, COMPRESS_ADDR, I_BLOCKS, I_COMPR_BLOCKS, I_SIZE, NEW_ADDR,
                  NULL_ADDR, OFFSET_OF_END_OF_I_EXT};
use crate::volume::dnode::{put64, Holder};
use crate::volume::Volume;

use super::cluster::Geometry;
use super::plan::{self, Slot};
use super::{compress_cluster, decompress_cluster, Chksum, Stored};

/// Why a cluster could not be turned into file bytes, as an errno. # C: O(1)
fn errno(e: super::CompressError) -> Errno { e.errno() }

impl<S: SectorSource> Volume<S> {
    /// The compression an inode's stored fields describe. # C: O(1)
    pub fn geometry(&self, inode: &Inode) -> Result<Geometry, Errno> {
        Geometry::new(inode.compress_algorithm, inode.log_cluster_size, inode.compress_flag)
            .map_err(errno)
    }

    /// One cluster's plain bytes, whatever shape it is stored in.
    ///
    /// Always a WHOLE cluster: a compressed image decodes to one, a plain
    /// cluster's holes read as zeroes, and a cluster the file has not reached
    /// yet is zeroes throughout. The file's size is applied by the caller.
    /// # C: O(cluster bytes)
    pub fn cluster_bytes(&self, inode: &Inode, ino: u32, g: &Geometry, first: u64)
        -> Result<Vec<u8>, Errno> {
        let addrs = self.cluster_addrs(inode, ino, g, first)?;
        if addrs.first() == Some(&COMPRESS_ADDR) {
            let live = super::data_blocks(&addrs).map_err(errno)?;
            let mut image = Vec::with_capacity(live.len() * BLKSIZE);
            for &a in live {
                if !self.sb.valid_main_blkaddr(a) { return Err(Errno::Eio); }
                image.extend_from_slice(&self.read_main_block(a)?);
            }
            let c = decompress_cluster(g, &image).map_err(errno)?;
            if let Chksum::Mismatch { .. } = c.chksum { return Err(Errno::Eio); }
            return Ok(c.data);
        }
        let mut out = vec![0u8; g.bytes()];
        for (i, &a) in addrs.iter().enumerate() {
            if crate::node::is_hole(a) { continue; }
            if !self.sb.valid_main_blkaddr(a) { return Err(Errno::Eio); }
            out[i * BLKSIZE..(i + 1) * BLKSIZE].copy_from_slice(&self.read_main_block(a)?);
        }
        Ok(out)
    }

    /// The addresses a cluster's slots hold, uninterpreted. # C: O(cluster blocks)
    pub(crate) fn cluster_addrs(&self, inode: &Inode, ino: u32, g: &Geometry, first: u64)
        -> Result<Vec<u32>, Errno> {
        (0..g.blocks() as u64).map(|i| self.stored_addr(inode, ino, first + i)).collect()
    }

    /// The saved-block count the inode records. # C: O(1 block)
    pub fn compr_blocks(&self, ino: u32) -> Result<u64, Errno> {
        let inode = self.read_inode(ino)?;
        if !compr_blocks_fits(&inode) { return Ok(0); }
        let block = self.inode_bytes(ino)?;
        Ok(le64(&block, I_COMPR_BLOCKS).unwrap_or(0))
    }

    /// Write `data` into a compressed file at byte offset `off`.
    ///
    /// Cluster by cluster, each one read back before it is rewritten. What
    /// landed stays landed when a later cluster fails: reporting the whole
    /// call as failed would tell the caller its file is unchanged when it is
    /// not.
    /// # C: O(bytes written + clusters touched * cluster bytes)
    pub fn write_compressed(&mut self, ino: u32, off: u64, data: &[u8]) -> Result<usize, Errno> {
        self.writable_or_err()?;
        if data.is_empty() { return Ok(0); }
        let inode = self.read_inode(ino)?;
        let g = self.geometry(&inode)?;
        if inode.inline_data() { self.convert_inline(ino)?; }
        let span = g.bytes() as u64;
        let end = off.checked_add(data.len() as u64).ok_or(Errno::Efbig)?;
        let size = end.max(self.read_inode(ino)?.size);
        let (mut done, mut stopped) = (0usize, None);
        let mut at = off;
        while at < end {
            let first = (at / span) * g.blocks() as u64;
            let base = (at / span) * span;
            let take = (base + span).min(end) - at;
            let put = (at - base) as usize;
            match self.splice_cluster(ino, &g, first, put, &data[done..done + take as usize], size)
            {
                Ok(()) => { done += take as usize; at += take; }
                Err(e) => { stopped = Some(e); break; }
            }
        }
        if done > 0 { self.stamp_size(ino, (off + done as u64).max(inode.size))?; }
        match stopped {
            Some(e) if done == 0 => Err(e),
            _ => Ok(done),
        }
    }

    /// Put `data` at `put` bytes into one cluster and store the cluster again.
    /// # C: O(cluster bytes)
    fn splice_cluster(&mut self, ino: u32, g: &Geometry, first: u64, put: usize, data: &[u8],
                      size: u64) -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        let mut planebytes = self.cluster_bytes(&inode, ino, g, first)?;
        planebytes[put..put + data.len()].copy_from_slice(data);
        let touched: Vec<bool> = (0..g.blocks())
            .map(|i| {
                let (s, e) = (i * BLKSIZE, (i + 1) * BLKSIZE);
                put < e && put + data.len() > s
            })
            .collect();
        self.store_cluster(ino, g, first, &planebytes, size, &touched)
    }

    /// Store one cluster's plain bytes, compressed if both rules allow it.
    ///
    /// `touched` says which blocks this write itself covered; a block that was
    /// neither touched nor already allocated stays a hole, which is what keeps
    /// a sparse file sparse. A cluster that WAS compressed has no holes to
    /// keep, so every block of it is written.
    /// # C: O(cluster bytes)
    pub(crate) fn store_cluster(&mut self, ino: u32, g: &Geometry, first: u64, plainbytes: &[u8],
                                size: u64, touched: &[bool]) -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        let old = self.cluster_addrs(&inode, ino, g, first)?;
        let was = plan::compressed_extent(&old);
        let stored = if plan::may_compress(first, g.blocks(), size, BLKSIZE) {
            compress_cluster(g, plainbytes).map_err(errno)?
        } else {
            Stored::Plain
        };
        let (slots, payload, now) = match stored {
            Stored::Compressed(img) => {
                let s = plan::compressed(g.blocks(), img.blocks);
                (s, img.bytes, Some(img.blocks + 1))
            }
            Stored::Plain => {
                // A cluster that WAS compressed has no holes to keep — every
                // block of it was materialised by the decompression — so all
                // of them are written. Past the end of the file none are: the
                // reference writes them and frees them again, which reaches
                // the same slots by a longer road.
                let live: Vec<bool> = (0..g.blocks())
                    .map(|i| {
                        let start = (first + i as u64) * BLKSIZE as u64;
                        start < size
                            && (was.is_some()
                                || touched[i]
                                || super::cluster::is_data_addr(old[i]))
                    })
                    .collect();
                (plan::plain(&live), plainbytes.to_vec(), None)
            }
        };
        self.rebalance(ino, &old, &slots)?;
        self.lay_out(ino, first, &old, &slots, &payload)?;
        let cur = self.compr_blocks(ino)?;
        let after = plan::compr_blocks_after(cur, g.blocks(), was, now);
        self.stamp_compr_blocks(ino, after)
    }

    /// Charge or refund the difference in slots the file owns.
    ///
    /// Before anything is written: a refusal after the blocks are allocated
    /// leaves them charged to nobody and the file pointing at them.
    /// # C: O(cluster blocks)
    fn rebalance(&mut self, ino: u32, old: &[u32], slots: &[Slot]) -> Result<(), Errno> {
        let before = plan::cluster_blocks(old) as u64;
        let after = slots.iter().filter(|s| s.owned()).count() as u64;
        if after > before { return self.charge_space(ino, (after - before) * BLKSIZE as u64); }
        if before > after { return self.uncharge_space(ino, (before - after) * BLKSIZE as u64); }
        Ok(())
    }

    /// Write the payload blocks and record every slot's new address.
    /// # C: O(cluster bytes)
    fn lay_out(&mut self, ino: u32, first: u64, old: &[u32], slots: &[Slot], payload: &[u8])
        -> Result<(), Errno> {
        for (i, slot) in slots.iter().enumerate() {
            let (holder, ofs) = self.dnode_for_write(ino, first + i as u64)?;
            // The sentinel is a mark, not a block: handing it to the allocator
            // as the address being replaced looks up a segment that does not
            // exist.
            let old_block = if old[i] == COMPRESS_ADDR { NULL_ADDR } else { old[i] };
            let addr = match slot {
                Slot::Sentinel => {
                    self.release_block(old_block)?;
                    COMPRESS_ADDR
                }
                Slot::Data(n) => {
                    let at = n * BLKSIZE;
                    let owner = match holder { Holder::Inode => ino, Holder::Direct(nid) => nid };
                    let page = payload.get(at..at + BLKSIZE).ok_or(Errno::Eio)?;
                    self.write_data(owner, ofs as u16, false, old_block, page)?
                }
                Slot::Reserved => {
                    self.release_block(old_block)?;
                    NEW_ADDR
                }
                Slot::Hole => {
                    self.release_block(old_block)?;
                    NULL_ADDR
                }
            };
            self.set_holder_addr(ino, holder, ofs, addr)?;
        }
        Ok(())
    }

    /// Shorten (or extend) a compressed file to `len`.
    ///
    /// Blocks are freed a whole CLUSTER at a time; the cluster the new end
    /// falls inside is rewritten instead, with everything past the end zeroed
    /// and the blocks it no longer covers dropped. It comes back plain, since
    /// the file's size now stops part way through it.
    /// # C: O(clusters released)
    pub fn truncate_compressed(&mut self, ino: u32, len: u64) -> Result<(), Errno> {
        self.writable_or_err()?;
        let inode = self.read_inode(ino)?;
        let g = self.geometry(&inode)?;
        if inode.inline_data() { self.convert_inline(ino)?; }
        if len >= inode.size { return self.stamp_size(ino, len); }
        let span = g.bytes() as u64;
        let free_from = len.div_ceil(span) * span;
        self.free_clusters(ino, &g, free_from, inode.size)?;
        if len % span != 0 {
            let base = (len / span) * span;
            let first = (len / span) * g.blocks() as u64;
            let inode = self.read_inode(ino)?;
            let mut planebytes = self.cluster_bytes(&inode, ino, &g, first)?;
            planebytes[(len - base) as usize..].fill(0);
            // Every block still inside the file is written; the rest of the
            // cluster is dropped rather than written and freed again.
            let all = vec![true; g.blocks()];
            self.store_cluster(ino, &g, first, &planebytes, len, &all)?;
        }
        self.truncate_tail(ino, free_from / BLKSIZE as u64)?;
        self.stamp_size(ino, len)
    }

    /// Release every cluster from `from` bytes to the end of the file.
    /// # C: O(clusters released)
    fn free_clusters(&mut self, ino: u32, g: &Geometry, from: u64, size: u64)
        -> Result<(), Errno> {
        let span = g.bytes() as u64;
        let mut at = from;
        while at < size {
            let first = (at / span) * g.blocks() as u64;
            let inode = self.read_inode(ino)?;
            let old = self.cluster_addrs(&inode, ino, g, first)?;
            if plan::cluster_blocks(&old) != 0 {
                let was = plan::compressed_extent(&old);
                let slots = vec![Slot::Hole; g.blocks()];
                self.rebalance(ino, &old, &slots)?;
                self.lay_out(ino, first, &old, &slots, &[])?;
                let cur = self.compr_blocks(ino)?;
                let after = plan::compr_blocks_after(cur, g.blocks(), was, None);
                self.stamp_compr_blocks(ino, after)?;
            }
            at += span;
        }
        Ok(())
    }

    /// The blocks a compressed file holds.
    ///
    /// The general count walks the address tree and skips the reservations a
    /// compressed cluster leaves behind, because for every other kind of file
    /// a reservation is a hole. Here they are space the file is charged for
    /// and must be counted, or the recorded saving describes blocks the file
    /// does not hold — which a checker reads as a corrupt inode.
    /// # C: O(file blocks)
    pub fn compressed_iblocks(&self, ino: u32) -> Result<u64, Errno> {
        let inode = self.read_inode(ino)?;
        let mut n = self.count_blocks(ino)?;
        if inode.inline_data() { return Ok(n); }
        let g = self.geometry(&inode)?;
        let span = g.bytes() as u64;
        let mut at = 0u64;
        while at < inode.size {
            let first = (at / span) * g.blocks() as u64;
            let addrs = self.cluster_addrs(&inode, ino, &g, first)?;
            n += addrs.iter().filter(|&&a| a == NEW_ADDR).count() as u64;
            at += span;
        }
        Ok(n)
    }

    /// Record the file's size and the blocks it now holds. # C: O(file blocks)
    fn stamp_size(&mut self, ino: u32, size: u64) -> Result<(), Errno> {
        self.stamp_inode(ino, |b| put64(b, I_SIZE, size))?;
        let blocks = self.compressed_iblocks(ino)?;
        self.stamp_inode(ino, |b| {
            put64(b, I_SIZE, size);
            b[I_BLOCKS..I_BLOCKS + 8].copy_from_slice(&blocks.max(1).to_le_bytes());
        })?;
        self.refresh_extent(ino)
    }

    /// Record the saved-block count, when the inode is wide enough to hold it.
    /// # C: O(1 block)
    fn stamp_compr_blocks(&mut self, ino: u32, n: u64) -> Result<(), Errno> {
        if !compr_blocks_fits(&self.read_inode(ino)?) { return Ok(()); }
        self.stamp_inode(ino, |b| put64(b, I_COMPR_BLOCKS, n))
    }
}

/// Whether the inode's extra attributes reach the saved-block count.
///
/// An inode too narrow to hold it does not get one invented elsewhere: the
/// count would then live only in memory and disagree with the medium after
/// the next mount.
/// # C: O(1)
fn compr_blocks_fits(inode: &Inode) -> bool {
    I_COMPR_BLOCKS + 8 <= OFFSET_OF_END_OF_I_EXT + inode.extra_isize
}
