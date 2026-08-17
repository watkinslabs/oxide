//! The orphan list a volume carries, and what a checkpoint does with it.
//!
//! An inode whose last name is gone is NOT free: something may still hold it
//! open, its blocks are still readable through that handle, and freeing them
//! would hand the same blocks to the next file while the reader is pointed at
//! them. So losing a name never frees anything — it parks. Recording the debt
//! in memory alone is easy and wrong: a crash between the unlink and the last
//! close leaves an inode no name reaches and no checkpoint mentions, whose
//! blocks stay counted live forever.
//!
//! So the list is parked in the checkpoint pack itself, between the payload
//! and the summaries, and the next mount frees what the crash could not. The
//! flag in the checkpoint is what says the blocks are there; the gap between
//! where the payload ends and where the summaries start is what says how many.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::CP_ORPHAN_PRESENT_FLAG;
use crate::uapi::{I_CTIME, I_CTIME_NSEC, I_LINKS, I_SIZE};

use super::super::dnode::{put32, put64};
use super::super::Volume;
use super::block;

impl<S: SectorSource> Volume<S> {
    /// The inodes waiting to be freed, in inode order. # C: O(orphans)
    pub fn orphan_list(&self) -> Vec<u32> { self.orphans.iter().copied().collect() }

    /// Whether `ino` is parked. # C: O(log orphans)
    pub fn is_orphan(&self, ino: u32) -> bool { self.orphans.contains(&ino) }

    /// The most orphans this volume's geometry can park. # C: O(1)
    pub fn max_orphans(&self) -> u64 {
        block::max_orphans(self.sb.blks_per_seg(), self.sb.cp_payload)
    }

    /// Park `ino`, or refuse when the pack has no room left for it.
    ///
    /// The refusal is what keeps the pack inside its segment; a pack that
    /// outgrows one overwrites the area beyond it.
    /// # C: O(log orphans)
    pub fn add_orphan(&mut self, ino: u32) -> Result<(), Errno> {
        self.writable_or_err()?;
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::Orphan) {
            return Err(Errno::Enospc);
        }
        if self.orphans.contains(&ino) { return Ok(()); }
        if self.orphans.len() as u64 >= self.max_orphans() { return Err(Errno::Enospc); }
        self.orphans.insert(ino);
        self.dirty = true;
        Ok(())
    }

    /// Take `ino` off the list WITHOUT freeing it, for a name that came back.
    /// Returns whether it was on the list. # C: O(log orphans)
    pub fn unpark_orphan(&mut self, ino: u32) -> bool {
        let was = self.orphans.remove(&ino);
        if was { self.dirty = true; }
        was
    }

    /// Free a parked inode and everything it owns. # C: O(blocks it has)
    pub fn release_orphan(&mut self, ino: u32) -> Result<(), Errno> {
        self.writable_or_err()?;
        if !self.orphans.remove(&ino) { return Ok(()); }
        self.free_inode(ino)?;
        self.dirty = true;
        Ok(())
    }

    /// Reserve room on the list for a name that is about to go.
    ///
    /// Asked BEFORE the entry is taken out, which is the whole reason it is
    /// separate from the parking itself: a removal that finds the list full
    /// after the name is gone has an inode it can neither park nor free, and
    /// the blocks stay counted live with nothing recording the debt. Refused
    /// here, the caller still has a directory it has not touched.
    /// # C: O(1)
    pub(crate) fn reserve_orphan(&self) -> Result<(), Errno> {
        if self.orphans.len() as u64 >= self.max_orphans() { return Err(Errno::Enospc); }
        Ok(())
    }

    /// Free `ino` now that the last reference to it is gone.
    ///
    /// The terminal point of an inode's life, and the only place a parked
    /// inode is reclaimed without a crash in between: an inode whose last name
    /// went while a handle still held it is on the list, and this is the moment
    /// that handle is gone. One that was given a name in the meantime is no
    /// longer on the list and is left where it is.
    /// # C: O(blocks it has) when it was parked, O(1) otherwise
    pub fn evict_inode(&mut self, ino: u32) -> Result<(), Errno> {
        if self.orphans.contains(&ino) { return self.release_orphan(ino); }
        // Nothing holds the file any more, so nothing is going to read its
        // clusters again soon; the blocks it cached are held for no one. A
        // file being FREED needs no such call — releasing its blocks drops
        // their cached copies by address.
        self.compress_cache.invalidate_ino(ino);
        Ok(())
    }

    /// A name for `ino` has gone: drop the stored link count by what that name
    /// was worth, and PARK the inode when it reaches zero.
    ///
    /// Parking rather than freeing is the contract, and the reason the orphan
    /// list exists at all. A descriptor that still holds the file goes on
    /// reading its blocks after the name is gone, so freeing here hands those
    /// blocks to the next file while a reader is still pointed at them — the
    /// reader then sees somebody else's bytes. The inode outlives its last
    /// name, and `evict_inode` — the last reference, the only point that knows
    /// no reader is left — is what frees it.
    ///
    /// Doing that in memory alone would be easy and wrong: a crash between the
    /// removal and that last close leaves an inode no name reaches and no
    /// checkpoint mentions, whose blocks stay counted live forever. The list is
    /// written into the checkpoint pack, so the next mount frees what the crash
    /// interrupted.
    ///
    /// A directory's name is worth TWO of its links — the entry in its parent
    /// and its own `.` — and its parent loses the link the child's `..` held.
    /// An emptied directory is truncated as it goes, because a parked directory
    /// that still claims a size describes blocks its own index no longer names.
    /// # C: O(1 block)
    pub(crate) fn drop_nlink(&mut self, dir: u32, ino: u32, is_dir: bool, now: (u64, u32))
        -> Result<(), Errno> {
        if is_dir {
            let up = self.read_inode(dir)?.links.saturating_sub(1).max(1);
            self.stamp_inode(dir, |b| put32(b, I_LINKS, up))?;
        }
        let worth = if is_dir { 2 } else { 1 };
        let left = self.read_inode(ino)?.links.saturating_sub(worth);
        self.stamp_inode(ino, |b| {
            put32(b, I_LINKS, left);
            if is_dir { put64(b, I_SIZE, 0); }
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })?;
        // The stored count is at zero BEFORE the parking, so an inode on the
        // list never claims a link it does not have: one that did would read as
        // reachable to anything that finds it without the list — a checker, or a
        // mount whose pack was lost.
        if left == 0 { self.add_orphan(ino)?; }
        Ok(())
    }

    /// Blocks the next checkpoint must set aside for the list. # C: O(1)
    pub(crate) fn orphan_blocks(&self) -> u32 { block::blocks_for(self.orphans.len()) }


    /// The flag word a pack carrying this list must hold. # C: O(1)
    pub(crate) fn orphan_flag(&self, flags: u32) -> u32 {
        block::flag_word(flags, self.orphans.len())
    }

    /// Lay the list down at `start`, which is the block after the payload.
    /// # C: O(orphan blocks)
    pub(crate) fn write_orphans(&mut self, start: u32) -> Result<(), Errno> {
        for (i, b) in block::encode_all(&self.orphan_list()).iter().enumerate() {
            self.write_block(start + i as u32, b)?;
        }
        Ok(())
    }

    /// Free every inode the mounted pack parked.
    ///
    /// Runs at mount, before anything else can allocate: a node id still owned
    /// by an unreclaimed orphan handed out to a new file would give two inodes
    /// one number. A mount that may not write leaves the list alone — the
    /// blocks stay counted, which is recoverable, where a half-done reclaim on
    /// a medium that cannot record it is not.
    /// # C: O(orphan blocks + blocks they own)
    #[inline(never)]
    pub fn recover_orphans(&mut self) -> Result<(), Errno> {
        if !self.cp.has(CP_ORPHAN_PRESENT_FLAG) { return Ok(()); }
        if !self.writable { return Ok(()); }
        let payload = self.sb.cp_payload;
        let base = self.cp.start(self.sb.cp_blkaddr, self.sb.blks_per_seg()) + 1 + payload;
        let n = block::blocks_in_pack(self.cp.pack_start_sum, payload).ok_or(Errno::Einval)?;
        let mut inos: Vec<u32> = Vec::new();
        // The pack's orphan blocks are consecutive, so the whole list is
        // fetched as runs before it is decoded block by block.
        self.ra_meta_pages(base, n, crate::volume::readahead::RaMeta::Cp);
        for i in 0..n {
            let raw = self.read_block(base + i)?;
            let decoded = block::decode(&raw).ok_or(Errno::Einval)?;
            inos.extend_from_slice(&decoded.inos);
        }
        let any = !inos.is_empty();
        for ino in inos {
            // Reclaiming an orphan gives its blocks and its inode back to the
            // identity that owned them, so that identity's records are brought
            // in before the reclaim rather than from inside it.
            self.dquot_initialize(ino)?;
            self.free_inode(ino)?;
        }
        // Reclaiming an orphan is a recovery as much as replaying a chain is,
        // and the reference records both under the one condition.
        if any { self.sbi.recovered(); }
        // The pack on the medium still says orphans are present. Clearing the
        // bit here is what stops the NEXT checkpoint from carrying it forward
        // and sending a later mount back to blocks that no longer exist.
        self.cp.flags &= !CP_ORPHAN_PRESENT_FLAG;
        self.dirty = true;
        Ok(())
    }
}
