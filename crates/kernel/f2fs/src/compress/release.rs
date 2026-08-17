//! Handing the blocks compression saved back to the volume, and taking them
//! again.
//!
//! A compressed cluster does not give its space away as it is written: the
//! slots the image does not need stay RESERVED and the file goes on being
//! charged for the whole cluster, so a rewrite that compresses worse always has
//! somewhere to land (`plan`). RELEASE is the deliberate, one-off decision to
//! give that room up — after it the file cannot be written at all, which is
//! exactly what a caller distributing read-only images wants and why it is not
//! done automatically.
//!
//! Three counts move together and each is a different question:
//!
//! - the volume's own count, which the reservations were charged against;
//! - the file's block count, which is what a checker compares with the
//!   segment table;
//! - the file's saved-block count, which is how much of that charge
//!   compression had already made unnecessary.
//!
//! The SENTINEL is the subtle one. It occupies a slot and names no block, and
//! while the file is unreleased it is charged like any other reservation.
//! Releasing gives its charge back too — the slot stays where it is, because it
//! is what says the cluster is compressed at all — so a cluster of `n` blocks
//! whose image holds `c` of them hands back `n - c`, not `n - 1 - c`. Getting
//! that one block wrong in either direction is silent: too few and the space
//! never comes back, too many and the count describes blocks the file still
//! holds.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::COMPRESS_RELEASED;
use crate::uapi::{BLKSIZE, COMPRESS_ADDR, I_BLOCKS, I_COMPR_BLOCKS, I_INLINE, NEW_ADDR,
                  NULL_ADDR};
use crate::volume::dnode::put64;
use crate::volume::Volume;

use super::cluster::{is_data_addr, Geometry};

/// One cluster as the two walks read it.
struct Counted {
    /// Blocks of the stored image, the sentinel excluded.
    data: usize,
    /// Slots already standing reserved, which a release left behind when it
    /// failed part way and a fresh release has nothing to do with.
    reserved: usize,
}

impl<S: SectorSource> Volume<S> {
    /// Hand back every block `ino`'s compressed clusters saved.
    ///
    /// Reports the blocks handed back, which is what the caller is told.
    /// # C: O(file blocks)
    pub fn release_compress_blocks(&mut self, ino: u32) -> Result<u64, Errno> {
        self.writable_or_err()?;
        // The walk reads addresses, so every pending write has to have one.
        self.flush_data_pages(ino)?;
        let g = self.geometry(&self.read_inode(ino)?)?;
        let mut released = 0u64;
        let mut saved = self.compr_blocks(ino)?;
        // The flag goes on BEFORE the walk, as the state the file is entering
        // rather than one it reaches on success: a release interrupted part
        // way has already given blocks back, and a file that still read as
        // unreleased would let the next writer spend them twice.
        self.stamp_inode(ino, |b| b[I_INLINE] |= COMPRESS_RELEASED)?;
        let outcome = self.walk_clusters(ino, &g, |v, first, addrs, c| {
            let mut back = 0u64;
            for (i, &a) in addrs.iter().enumerate().skip(1) {
                if a != NEW_ADDR { continue; }
                let (h, ofs) = v.dnode_for_write(ino, first + i as u64)?;
                v.set_holder_addr(ino, h, ofs, NULL_ADDR)?;
                v.release_reservation();
                back += 1;
            }
            // The sentinel's own charge, given back while the sentinel stays:
            // the slot is what says this cluster is an image, and clearing it
            // would leave the blocks after it unreadable.
            v.release_reservation();
            back += 1;
            // A mark holds the OWNER'S quota as well as the volume's count —
            // the two move together everywhere a mark is made or unmade — so
            // both come back here. Giving back only the volume's half would
            // leave the file charged forever for room it no longer holds, and
            // the charge would survive every remount.
            v.uncharge_space(ino, back * BLKSIZE as u64)?;
            let n = (g.blocks() - c.data) as u64;
            released += n;
            saved = saved.saturating_sub(n);
            Ok(())
        });
        self.stamp_compress_counts(ino, saved)?;
        if let Err(e) = outcome {
            // Part of the saving is gone and part is still recorded, which is
            // a file only a check can put right. Reporting the error without
            // the mark would leave that state on the medium unannounced.
            if released > 0 && saved != 0 { self.sbi.set(crate::sbflags::bits::NEED_FSCK); }
            return Err(e);
        }
        Ok(released)
    }

    /// Take the saved blocks back, so the file can be written again.
    ///
    /// Reports the blocks re-reserved.
    /// # C: O(file blocks)
    pub fn reserve_compress_blocks(&mut self, ino: u32) -> Result<u64, Errno> {
        self.writable_or_err()?;
        self.flush_data_pages(ino)?;
        let g = self.geometry(&self.read_inode(ino)?)?;
        // A file that still records a saving was never released, so there is
        // nothing to take back and the slots are already the file's.
        if self.compr_blocks(ino)? != 0 { return Ok(0); }
        let mut reserved = 0u64;
        let mut saved = 0u64;
        let outcome = self.walk_clusters(ino, &g, |v, first, addrs, c| {
            let want = g.blocks() - c.data - c.reserved;
            // Every slot but one already stands reserved, so the one left is
            // the sentinel's own charge, which the cluster still holds.
            if c.reserved > 0 && want == 1 { return Ok(()); }
            // The owner's quota is taken BEFORE any slot changes: a refusal
            // afterwards would leave the file holding marks nobody is charged
            // for, which is the same hole as an uncharged block.
            v.charge_space(ino, want as u64 * BLKSIZE as u64)?;
            for (i, &a) in addrs.iter().enumerate().skip(1) {
                if a != NULL_ADDR { continue; }
                let (h, ofs) = v.dnode_for_write(ino, first + i as u64)?;
                v.set_holder_addr(ino, h, ofs, NEW_ADDR)?;
            }
            for _ in 0..want { v.charge_reservation(); }
            reserved += want as u64;
            saved += (g.blocks() - c.data) as u64;
            Ok(())
        });
        // The flag comes off only when every cluster was taken back: a file
        // half re-reserved is still a file whose blocks are partly the
        // volume's, and letting a writer at it would overrun them.
        if outcome.is_ok() { self.stamp_inode(ino, |b| b[I_INLINE] &= !COMPRESS_RELEASED)?; }
        self.stamp_compress_counts(ino, saved)?;
        if let Err(e) = outcome {
            if reserved > 0 && saved != 0 { self.sbi.set(crate::sbflags::bits::NEED_FSCK); }
            return Err(e);
        }
        Ok(reserved)
    }

    /// Walk every compressed cluster of `ino`, in file order.
    ///
    /// A cluster stored plain is skipped whole: its first slot is not the
    /// sentinel, so none of its blocks is a saving anyone can hand back.
    /// # C: O(file blocks)
    fn walk_clusters(
        &mut self, ino: u32, g: &Geometry,
        mut each: impl FnMut(&mut Self, u64, &[u32], &Counted) -> Result<(), Errno>,
    ) -> Result<(), Errno> {
        let last = self.read_inode(ino)?.size.div_ceil(BLKSIZE as u64);
        let mut first = 0u64;
        while first < last {
            let inode = self.read_inode(ino)?;
            let addrs = self.cluster_addrs(&inode, ino, g, first)?;
            if addrs.first() == Some(&COMPRESS_ADDR) {
                let c = count(&addrs);
                // An address inside a compressed cluster that is not a block of
                // this volume is a damaged index; acting on it would hand the
                // volume's count blocks that belong to its metadata.
                for &a in &addrs[1..] {
                    if is_data_addr(a) && !self.sb.valid_main_blkaddr(a) {
                        return Err(Errno::Euclean);
                    }
                }
                each(self, first, &addrs, &c)?;
            }
            first += g.blocks() as u64;
        }
        Ok(())
    }

    /// Record the file's block count and its saving, TOGETHER.
    ///
    /// The saving is bounded by the block count, so the pair is only ever
    /// consistent as a pair: written one at a time, whichever moves first
    /// leaves an inode the very next read refuses. A walk that stopped part
    /// way can leave a saving larger than the blocks that are left, and the
    /// bound is applied rather than the inode made unreadable — the damage is
    /// announced by the fsck mark the caller raises, not by an inode nothing
    /// can parse.
    /// # C: O(file blocks)
    fn stamp_compress_counts(&mut self, ino: u32, saved: u64) -> Result<(), Errno> {
        let blocks = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| {
            b[I_BLOCKS..I_BLOCKS + 8].copy_from_slice(&blocks.max(1).to_le_bytes());
            put64(b, I_COMPR_BLOCKS, saved.min(blocks.max(1)));
        })
    }
}

/// What one compressed cluster's slots hold. # C: O(cluster blocks)
fn count(addrs: &[u32]) -> Counted {
    Counted {
        data: addrs[1..].iter().filter(|&&a| is_data_addr(a)).count(),
        reserved: addrs[1..].iter().filter(|&&a| a == NEW_ADDR).count(),
    }
}
