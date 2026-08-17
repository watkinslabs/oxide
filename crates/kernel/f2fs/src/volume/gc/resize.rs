//! Shrinking a mounted volume onto fewer sections.
//!
//! Three separate accounts describe the volume's size and all three have to
//! agree afterwards, or the next mount refuses what it reads:
//!
//! - the SUPERBLOCK's counts, which say how much medium the volume covers;
//! - the CHECKPOINT's user block count, which says how much of it may hold
//!   data;
//! - the segment table and the logs, which say where the data actually is.
//!
//! So the order is fixed and is not free choice. The sections being given up
//! are emptied FIRST, while they still exist and their blocks are still
//! readable: a superblock that had already shrunk would make every address in
//! them out of range, and the cleaner could not so much as read the blocks it
//! is being asked to move. Only once the range is empty is the superblock
//! written, and only once THAT has landed does the checkpoint follow — a
//! checkpoint claiming space the superblock does not cover is what a mount
//! cross-checks for.
//!
//! Every failure puts back what it can and says so. A superblock that landed
//! and a checkpoint that did not is the one state that cannot be reasoned away
//! by the next mount, and it raises the mark that demands a check rather than
//! being reported as an ordinary error.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::CP_DISABLED_FLAG;
use crate::sbflags::bits;
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Take the volume down to `block_count` blocks.
    ///
    /// Only downwards: growing means medium that was not there when the volume
    /// was made, and nothing here can know it is there now.
    /// # C: O(blocks in the sections given up)
    pub fn resize_fs(&mut self, block_count: u64) -> Result<(), Errno> {
        self.writable_or_err()?;
        let old = self.sb.block_count;
        if block_count > old { return Err(Errno::Einval); }
        let per_sec = u64::from(self.sb.segs_per_sec) * u64::from(self.sb.blks_per_seg());
        if per_sec == 0 { return Err(Errno::Einval); }
        // A size that does not land on a section boundary would leave a part
        // section the allocator cannot express.
        if block_count % per_sec != 0 { return Err(Errno::Einval); }
        if block_count == old { return Ok(()); }
        // A volume already known to be inconsistent must not be rearranged:
        // the check that would repair it reads the geometry being changed.
        if self.sbi.is_set(bits::NEED_FSCK) { return Err(Errno::Euclean); }
        if self.opts.checkpoint_disabled || self.cp.flags & CP_DISABLED_FLAG != 0 {
            return Err(Errno::Einval);
        }
        let shrunk = old - block_count;
        let secs = u32::try_from(shrunk / per_sec).map_err(|_| Errno::Einval)?;
        if secs == 0 || secs >= self.sb.section_count { return Err(Errno::Einval); }
        // The space has to be free BEFORE it is taken, counting what the
        // privileged caller is holding in reserve: a volume that would be over
        // full the moment it shrank is refused rather than shrunk into.
        let held = self.valid_block_count + u64::from(self.opts.reserve_root);
        if shrunk + held > self.cp.user_block_count { return Err(Errno::Enospc); }

        let per_sec_segs = self.sb.segs_per_sec.max(1);
        let first_gone = (self.sb.section_count - secs) * per_sec_segs;
        self.free_segment_range(first_gone)?;

        let blks = i64::try_from(shrunk).map_err(|_| Errno::Einval)?;
        crate::sbwrite::edit::resize(&mut self.sb_raw, -i64::from(secs))?;
        let ro = !self.writable;
        if let Err(e) = crate::sbwrite::commit_super(&self.source, &mut self.sb_raw, false, ro,
                                                     &mut self.sbi) {
            // Nothing has changed but memory, so the edit goes back and the
            // volume is exactly the volume it was.
            let _ = crate::sbwrite::edit::resize(&mut self.sb_raw, i64::from(secs));
            return Err(e);
        }
        self.adopt_super()?;
        self.forget_segments_past_end();
        self.cp.user_block_count = self.cp.user_block_count.saturating_sub(blks as u64);
        self.dirty = true;
        if let Err(e) = self.commit() {
            // The superblock says one size and the checkpoint another, which
            // is the one outcome the next mount cannot resolve on its own.
            self.sbi.set(bits::NEED_FSCK);
            return Err(e);
        }
        Ok(())
    }

    /// Empty every segment from `first_gone` to the end of the main area.
    ///
    /// The allocator is fenced off the range for the whole of it, or the
    /// cleaner would move the blocks it is emptying straight back in — and a
    /// log left open inside the range would go on appending to a segment that
    /// is about to stop existing.
    /// # C: O(blocks in the range)
    fn free_segment_range(&mut self, first_gone: u32) -> Result<(), Errno> {
        self.load_segments()?;
        self.segstate.resize_barrier = Some(first_gone);
        let outcome = self.empty_range(first_gone);
        self.segstate.resize_barrier = None;
        outcome
    }

    /// # C: O(blocks in the range)
    fn empty_range(&mut self, first_gone: u32) -> Result<(), Errno> {
        let end = self.sb.segment_count_main;
        let per_sec = self.sb.segs_per_sec.max(1);
        // The logs go first: a log inside the range is the one thing cleaning
        // cannot move, because the cleaner leaves a log's own segment alone.
        for log in 0..self.curseg.len() {
            if self.curseg[log].segno == crate::uapi::NULL_SEGNO { continue; }
            if self.curseg[log].segno >= first_gone { self.open_segment(log)?; }
        }
        let mut at = first_gone;
        while at < end {
            self.gc_section(at)?;
            at += per_sec;
        }
        // What cleaning emptied is prefree, and prefree is not empty as far as
        // the next mount is concerned: the checkpoint on the medium still
        // names those blocks. The checkpoint here is what makes the range
        // genuinely unused before the superblock stops covering it.
        self.commit()?;
        for segno in first_gone..end {
            // Not `seg_is_free`: the fence this runs under makes every segment
            // in the range unfree by construction, and what matters is that
            // nothing is left LIVE in it.
            if self.seg_valid(segno) != 0 || self.is_current(segno) {
                return Err(Errno::Eagain);
            }
        }
        Ok(())
    }

    /// Drop the loaded table's tail once the volume no longer covers it.
    ///
    /// A dirty entry for a segment past the end would be written into the
    /// segment table for a segment that does not exist, and the count the
    /// checkpoint records is taken over the table this trims.
    /// # C: O(dirty segments)
    fn forget_segments_past_end(&mut self) {
        let end = self.sb.segment_count_main;
        if let Some(t) = self.sit.as_mut() { t.truncate(end as usize); }
        self.sit_dirty.retain(|&s| s < end);
        self.segstate.prefree.retain(|&s| s < end);
    }
}
