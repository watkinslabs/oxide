//! The orphan list a volume carries, and what a checkpoint does with it.
//!
//! An inode whose last name is gone is NOT free while something still holds it
//! open: its blocks are still readable through the open handle, and a reader
//! that freed them would hand the same blocks to the next file. Freeing it at
//! the last close is easy in memory and wrong on the medium — a crash between
//! the unlink and that close leaves an inode no name reaches and no checkpoint
//! mentions, whose blocks stay counted live forever.
//!
//! So the list is parked in the checkpoint pack itself, between the payload
//! and the summaries, and the next mount frees what the crash could not. The
//! flag in the checkpoint is what says the blocks are there; the gap between
//! where the payload ends and where the summaries start is what says how many.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::CP_ORPHAN_PRESENT_FLAG;
use crate::uapi::{I_CTIME, I_CTIME_NSEC, I_LINKS};

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

    /// Record a holder of `ino`. # C: O(log opens)
    pub fn open_inode(&mut self, ino: u32) { *self.opens.entry(ino).or_insert(0) += 1; }

    /// Whether anything still holds `ino`. # C: O(log opens)
    pub fn inode_is_open(&self, ino: u32) -> bool { self.opens.contains_key(&ino) }

    /// Drop a holder of `ino`, freeing it when it was the last one and the
    /// inode is parked. This is the only place an orphan is reclaimed without
    /// a crash in between.
    /// # C: O(blocks it has) on the last close, O(log opens) otherwise
    pub fn close_inode(&mut self, ino: u32) -> Result<(), Errno> {
        let left = match self.opens.get_mut(&ino) {
            Some(n) => { *n = n.saturating_sub(1); *n }
            None => 0,
        };
        if left > 0 { return Ok(()); }
        self.opens.remove(&ino);
        if self.orphans.contains(&ino) { return self.release_orphan(ino); }
        // Nothing holds the file any more, so nothing is going to read its
        // clusters again soon; the blocks it cached are held for no one. A
        // file being FREED needs no such call — releasing its blocks drops
        // their cached copies by address.
        self.compress_cache.invalidate_ino(ino);
        Ok(())
    }

    /// The last name of `ino` has gone: free it, or park it when something
    /// still holds it open.
    ///
    /// The stored link count goes to zero either way. A parked inode that
    /// still claims a link reads as reachable to anything that finds it
    /// without the orphan list — a checker, or a mount whose pack was lost.
    /// # C: O(blocks it has) when freed, O(1 block) when parked
    pub(crate) fn drop_last_link(&mut self, ino: u32, now: (u64, u32)) -> Result<(), Errno> {
        if !self.inode_is_open(ino) { return self.free_inode(ino); }
        self.add_orphan(ino)?;
        self.stamp_inode(ino, |b| {
            put32(b, I_LINKS, 0);
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })
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
    pub fn recover_orphans(&mut self) -> Result<(), Errno> {
        if !self.cp.has(CP_ORPHAN_PRESENT_FLAG) { return Ok(()); }
        if !self.writable { return Ok(()); }
        let payload = self.sb.cp_payload;
        let base = self.cp.start(self.sb.cp_blkaddr, self.sb.blks_per_seg()) + 1 + payload;
        let n = block::blocks_in_pack(self.cp.pack_start_sum, payload).ok_or(Errno::Einval)?;
        let mut inos: Vec<u32> = Vec::new();
        for i in 0..n {
            let raw = self.read_block(base + i)?;
            let decoded = block::decode(&raw).ok_or(Errno::Einval)?;
            inos.extend_from_slice(&decoded.inos);
        }
        let any = !inos.is_empty();
        for ino in inos { self.free_inode(ino)?; }
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
