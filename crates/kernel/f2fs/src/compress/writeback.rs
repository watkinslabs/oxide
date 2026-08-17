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
use crate::uapi::{BLKSIZE, COMPRESS_ADDR, I_BLOCKS, I_COMPR_BLOCKS, I_SIZE, NEW_ADDR,
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
                self.io_account(crate::stats::iostat::Io::FsDataRead, BLKSIZE as u64, true);
                self.io_read_folio(0);
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
            self.io_account(crate::stats::iostat::Io::FsDataRead, BLKSIZE as u64, false);
            self.io_read_folio(0);
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
        Ok(self.read_inode(ino)?.compr_blocks)
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
        // Whether a write comes out compressed at all is the MOUNT's decision
        // where the mount was given it, and the caller's where it was not: a
        // volume mounted for caller-driven compression writes plain and stays
        // plain until the rewrite command asks otherwise, which is the whole
        // arrangement.
        let compress = self.opts.compress.mode == crate::opts::CompressMode::Fs;
        self.store_cluster_shaped(ino, g, first, &planebytes, size, &touched, compress)
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
        self.store_cluster_shaped(ino, g, first, plainbytes, size, touched, true)
    }

    /// The same, with the choice of shape taken away.
    ///
    /// `compress` false stores the cluster plain whatever the codec would have
    /// managed, which is what a caller asking for a file to be decompressed in
    /// place means — the two rules still decide the other direction, since a
    /// cluster that cannot be compressed cannot be compressed on request
    /// either.
    /// # C: O(cluster bytes)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_cluster_shaped(&mut self, ino: u32, g: &Geometry, first: u64,
                                       plainbytes: &[u8], size: u64, touched: &[bool],
                                       compress: bool) -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        let old = self.cluster_addrs(&inode, ino, g, first)?;
        let was = plan::compressed_extent(&old);
        // Read BEFORE the slots move: between the move and the stamp the two
        // counts describe different states of the file, and an inode read in
        // that window is refused as inconsistent.
        let cur = self.compr_blocks(ino)?;
        let stored = if compress && plan::may_compress(first, g.blocks(), size, BLKSIZE) {
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
        // A file whose saving has been handed back is no longer charged for
        // its sentinels, so the slot that holds one must not be given back a
        // second time. `cur` is the same test the reference makes: only a
        // released file has a sentinel and no saving recorded.
        self.lay_out(ino, first, &old, &slots, &payload, cur == 0)?;
        let after = plan::compr_blocks_after(cur, g.blocks(), was, now);
        self.stamp_counts(ino, Some(after))
    }

    /// Record the blocks the file holds and the saving it records, TOGETHER.
    ///
    /// The saving is bounded by the block count, so the pair is only ever
    /// consistent as a pair. Written one at a time, whichever moves first
    /// leaves the inode describing a file whose saving is larger than the
    /// blocks it holds — and the very next read of that inode, including the
    /// read the second stamp itself does, refuses it.
    /// # C: O(file blocks)
    fn stamp_counts(&mut self, ino: u32, compr: Option<u64>) -> Result<(), Errno> {
        let blocks = self.count_blocks(ino)?;
        let fits = compr_blocks_fits(&self.read_inode(ino)?);
        self.stamp_inode(ino, |b| {
            b[I_BLOCKS..I_BLOCKS + 8].copy_from_slice(&blocks.max(1).to_le_bytes());
            if let (Some(n), true) = (compr, fits) { put64(b, I_COMPR_BLOCKS, n); }
        })
    }

    /// Write the payload blocks and record every slot's new address.
    ///
    /// Three kinds of thing can sit in a slot and each is accounted its own
    /// way. A real block holds a bit in the segment table, a block of the
    /// volume's count and a block of the owner's quota. A MARK — the sentinel
    /// or a reservation — holds none of the first and none of the last: it
    /// names no block on the medium, so it sets no bit and costs no quota, but
    /// it does hold the volume's count, because the write it is holding room
    /// for has to find a block somewhere. An empty slot holds nothing.
    ///
    /// Getting the mark wrong in either direction is silent: released as if it
    /// were a block, it lowers a count nothing raised and looks up a segment
    /// that does not exist; not released at all, it leaks the count for the
    /// life of the volume.
    /// # C: O(cluster bytes)
    #[allow(clippy::too_many_arguments)]
    fn lay_out(&mut self, ino: u32, first: u64, old: &[u32], slots: &[Slot], payload: &[u8],
               released: bool) -> Result<(), Errno> {
        // Quota is charged for the blocks the cluster is about to GAIN before
        // any of them is allocated: a refusal afterwards would leave them
        // charged to nobody and the file pointing at them.
        let gained = slots
            .iter()
            .enumerate()
            .filter(|(i, s)| matches!(s, Slot::Data(_)) && !holds_block(old[*i]))
            .count() as u64;
        if gained > 0 { self.charge_space(ino, gained * BLKSIZE as u64)?; }
        for (i, slot) in slots.iter().enumerate() {
            let was = old[i];
            let target = match slot {
                Slot::Sentinel => COMPRESS_ADDR,
                Slot::Reserved => NEW_ADDR,
                Slot::Hole => NULL_ADDR,
                Slot::Data(_) => NULL_ADDR,
            };
            // A slot that is not changing is left alone entirely: reaching for
            // its node would CREATE the node a sparse file does not have.
            if !matches!(slot, Slot::Data(_)) && target == was { continue; }
            let (holder, ofs) = self.dnode_for_write(ino, first + i as u64)?;
            let addr = match slot {
                Slot::Data(n) => {
                    if is_mark(was) && !uncharged(was, released) { self.release_reservation(); }
                    let at = n * BLKSIZE;
                    let owner = match holder { Holder::Inode => ino, Holder::Direct(nid) => nid };
                    let page = payload.get(at..at + BLKSIZE).ok_or(Errno::Eio)?;
                    // Only a real block is handed to the allocator as the one
                    // being replaced; a mark names no segment to clear.
                    let carry = if holds_block(was) { was } else { NULL_ADDR };
                    let at_addr = self.write_data(owner, ofs as u16, false, carry, page)?;
                    // The generic writer has already charged this as file
                    // data; it is compressed data as well, and the compressed
                    // figure is what answers how much of the traffic was.
                    self.io_account(crate::stats::iostat::Io::FsCdata, BLKSIZE as u64, false);
                    at_addr
                }
                Slot::Sentinel | Slot::Reserved => {
                    if holds_block(was) { self.release_slot(ino, was)?; }
                    if !is_mark(was) { self.charge_reservation(); }
                    target
                }
                Slot::Hole => {
                    if holds_block(was) { self.release_slot(ino, was)?; }
                    if is_mark(was) && !uncharged(was, released) { self.release_reservation(); }
                    target
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
        // A file truncated away entirely stops being a released file: there is
        // no saving left that could have been handed back, and one that went
        // on reading as released could never be written again.
        if len == 0 && inode.has(crate::flags::COMPRESS_RELEASED) {
            self.stamp_inode(ino, |b| b[crate::uapi::I_INLINE] &= !crate::flags::COMPRESS_RELEASED)?;
        }
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
                let cur = self.compr_blocks(ino)?;
                let slots = vec![Slot::Hole; g.blocks()];
                self.lay_out(ino, first, &old, &slots, &[], cur == 0)?;
                let after = plan::compr_blocks_after(cur, g.blocks(), was, None);
                self.stamp_counts(ino, Some(after))?;
            }
            at += span;
        }
        Ok(())
    }

    /// Record the file's size and the blocks it now holds. # C: O(file blocks)
    fn stamp_size(&mut self, ino: u32, size: u64) -> Result<(), Errno> {
        // The size goes down first: the block count is read back off the
        // address tree, and the tree is what the size has to agree with.
        self.stamp_inode(ino, |b| put64(b, I_SIZE, size))?;
        self.stamp_counts(ino, None)?;
        self.refresh_extent(ino)
    }
}

/// Whether a slot names a block on the medium.
///
/// The sentinel and a reservation are MARKS: both occupy a slot and neither
/// names a block, so neither has a bit in the segment table to clear.
/// # C: O(1)
fn is_mark(addr: u32) -> bool { addr == NEW_ADDR || addr == COMPRESS_ADDR }

/// # C: O(1)
fn holds_block(addr: u32) -> bool { addr != NULL_ADDR && !is_mark(addr) }

/// Whether this slot's mark is one the volume has ALREADY stopped counting.
///
/// The sentinel of a file whose saving was handed back is exactly that: the
/// release gave its charge back and left the slot in place. Releasing it again
/// when the cluster is rewritten lowers a count nothing raised, and the volume
/// then believes it has more space than it does — free space that only ever
/// grows, and a checker that reports the wrong number.
/// # C: O(1)
fn uncharged(addr: u32, released: bool) -> bool { released && addr == COMPRESS_ADDR }

/// Whether the inode's extra attributes reach the saved-block count.
///
/// An inode too narrow to hold it does not get one invented elsewhere: the
/// count would then live only in memory and disagree with the medium after
/// the next mount.
/// # C: O(1)
fn compr_blocks_fits(inode: &Inode) -> bool {
    I_COMPR_BLOCKS + 8 <= OFFSET_OF_END_OF_I_EXT + inode.extra_isize
}
