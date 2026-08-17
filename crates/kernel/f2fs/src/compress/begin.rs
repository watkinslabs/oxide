//! What a write to a compressed file does BEFORE anything is on the medium.
//!
//! Nothing here allocates and nothing here compresses. A write takes the room
//! and the owner's quota for the slots it will need, writes a RESERVATION into
//! each of them, and leaves the file's plain bytes in the mapping; the codec
//! runs once, over a whole cluster, when the pages are placed (`place`).
//!
//! Which of two shapes a write takes is decided by the cluster it lands in,
//! not by the file's flag:
//!
//! - A cluster ALREADY stored as an image cannot be changed a block at a time.
//!   It is read back whole, patched, and every one of its blocks is left dirty
//!   in the mapping — because the image covers all of them, so all of them are
//!   rewritten.
//! - A cluster not yet stored as an image is written block by block, exactly
//!   as an uncompressed file's write is. Each block reserves its own slot, and
//!   once every slot of the cluster holds one the placement is free to make an
//!   image out of it.
//!
//! That second shape is what makes the placement safe: a cluster is turned
//! into an image only over slots that are ALREADY paid for, so choosing to
//! compress can never ask the volume for room — and a write the caller was
//! told had landed can never be refused afterwards.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::{BLKSIZE, COMPRESS_ADDR, I_SIZE, NULL_ADDR};
use crate::volume::dnode::put64;
use crate::volume::Volume;

use super::cluster::Geometry;

impl<S: SectorSource> Volume<S> {
    /// Write `data` into a compressed file at byte offset `off`.
    ///
    /// Cluster by cluster. What landed stays landed when a later cluster
    /// fails: reporting the whole call as failed would tell the caller its
    /// file is unchanged when it is not.
    /// # C: O(bytes written + image clusters touched * cluster bytes)
    pub fn write_compressed(&mut self, ino: u32, off: u64, data: &[u8]) -> Result<usize, Errno> {
        self.writable_or_err()?;
        if data.is_empty() { return Ok(0); }
        let inode = self.read_inode(ino)?;
        let g = self.geometry(&inode)?;
        if inode.inline_data() { self.convert_inline(ino)?; }
        let span = g.bytes() as u64;
        let end = off.checked_add(data.len() as u64).ok_or(Errno::Efbig)?;
        let (mut done, mut stopped) = (0usize, None);
        let mut at = off;
        while at < end {
            let base = (at / span) * span;
            let first = (at / span) * g.blocks() as u64;
            let take = ((base + span).min(end) - at) as usize;
            let put = (at - base) as usize;
            // A cluster that could not take the whole of its share still took
            // part of it, and the part that landed is the caller's: reporting
            // the cluster as a whole failure would tell the caller its bytes
            // are not there when some of them are, and the next read would
            // return them.
            let (took, err) = self.begin_cluster(ino, &g, first, put, &data[done..done + take]);
            done += took;
            at += took as u64;
            if let Some(e) = err { stopped = Some(e); break; }
        }
        // What landed is recorded even when the rest did not. A reservation
        // counts as a block the file holds, which is what makes the count
        // right before any address is chosen; the stored RUN is deliberately
        // not recomputed here, because the reservations name nowhere and
        // recomputing over them shortens the run to nothing.
        if done > 0 {
            let size = (off + done as u64).max(self.read_inode(ino)?.size);
            let blocks = self.count_blocks(ino)?;
            self.stamp_inode(ino, |b| {
                put64(b, I_SIZE, size);
                Self::set_iblocks(b, blocks);
            })?;
        }
        match stopped {
            Some(e) if done == 0 => Err(e),
            _ => Ok(done),
        }
    }

    /// Take everything one cluster's worth of a write needs, in whichever of
    /// the two shapes that cluster is in.
    ///
    /// Reports the bytes that landed and, if it stopped, why. Two answers
    /// rather than a `Result` because both halves matter: a refusal that
    /// accepted nothing and a refusal that accepted three blocks of four are
    /// different facts about the file, and a caller told only the error would
    /// report the whole write as having no effect.
    /// # C: O(cluster bytes)
    fn begin_cluster(&mut self, ino: u32, g: &Geometry, first: u64, put: usize, data: &[u8])
        -> (usize, Option<Errno>) {
        let head = match self.read_inode(ino).and_then(|i| self.stored_addr(&i, ino, first)) {
            Ok(a) => a,
            Err(e) => return (0, Some(e)),
        };
        if head != COMPRESS_ADDR { return self.begin_blocks(ino, first, put, data); }
        match self.begin_image(ino, g, first, put, data) {
            Ok(()) => (data.len(), None),
            Err(e) => (0, Some(e)),
        }
    }

    /// A cluster not stored as an image: one reservation per block touched.
    /// # C: O(bytes)
    fn begin_blocks(&mut self, ino: u32, first: u64, put: usize, data: &[u8])
        -> (usize, Option<Errno>) {
        let mut done = 0usize;
        while done < data.len() {
            let pos = put + done;
            let index = first + (pos / BLKSIZE) as u64;
            let skew = pos % BLKSIZE;
            let take = (BLKSIZE - skew).min(data.len() - done);
            if let Err(e) = self.write_one_block(ino, index, skew, &data[done..done + take]) {
                return (done, Some(e));
            }
            done += take;
        }
        (done, None)
    }

    /// A cluster stored as an image: read it back whole, patch it, and leave
    /// every block of it dirty.
    ///
    /// All of them, not only the ones the write covered. The image is one
    /// object spanning the whole cluster, so placing it rewrites every block —
    /// a page left behind clean would be a block the placement had no bytes
    /// for.
    ///
    /// All or nothing, which is why every slot is held before any page is
    /// filed. An image cannot be half-written: a cluster whose mapping held the
    /// patch for two of its blocks and the old bytes for the other two would be
    /// compressed as that mixture, and the write the caller was told had failed
    /// would be half on the medium.
    /// # C: O(cluster bytes)
    fn begin_image(&mut self, ino: u32, g: &Geometry, first: u64, put: usize, data: &[u8])
        -> Result<(), Errno> {
        let mut plain = self.cluster_now(ino, g, first)?;
        plain[put..put + data.len()].copy_from_slice(data);
        for i in 0..g.blocks() as u64 { self.reserve_cluster_slot(ino, first + i)?; }
        // The pages go in only once every slot is held, and AFTER the slots:
        // writing a reservation drops whatever the mapping holds for that
        // offset, so filing a page first would file the bytes and then throw
        // them away.
        for i in 0..g.blocks() as u64 {
            let at = i as usize * BLKSIZE;
            self.data_cache.write(ino, first + i, plain[at..at + BLKSIZE].to_vec())?;
        }
        Ok(())
    }

    /// A cluster's plain bytes as the FILE has them now: what the medium
    /// stores, overlaid with every page the mapping holds.
    ///
    /// The overlay is not an optimisation. A page dirtied by an earlier write
    /// and not yet placed is the only copy of those bytes — its slot names no
    /// block — so a read that went to the medium alone would lose the earlier
    /// write and write the loss back.
    /// # C: O(cluster bytes)
    pub(crate) fn cluster_now(&self, ino: u32, g: &Geometry, first: u64)
        -> Result<Vec<u8>, Errno> {
        let inode = self.read_inode(ino)?;
        let mut plain = self.cluster_bytes(&inode, ino, g, first)?;
        for i in 0..g.blocks() as u64 {
            let Some(page) = self.data_cache.peek(ino, first + i) else { continue };
            if page.len() != BLKSIZE { return Err(Errno::Eio); }
            let at = i as usize * BLKSIZE;
            plain[at..at + BLKSIZE].copy_from_slice(&page);
        }
        Ok(plain)
    }

    /// Hold one cluster slot that holds nothing yet.
    ///
    /// A slot already holding a block, a reservation or the sentinel is
    /// already paid for and is left exactly as it is.
    /// # C: O(indirection depth) blocks
    fn reserve_cluster_slot(&mut self, ino: u32, index: u64) -> Result<(), Errno> {
        let (holder, ofs) = self.dnode_for_write(ino, index)?;
        if self.holder_addr(ino, holder, ofs)? != NULL_ADDR { return Ok(()); }
        self.reserve_data_slot(ino, holder, ofs)
    }
}
