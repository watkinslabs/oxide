//! Writing a checkpoint: making everything this mount changed durable.
//!
//! A checkpoint is what turns a pile of out-of-place writes into a filesystem
//! state. Until one is written the medium still describes the PREVIOUS state
//! and a crash loses the work — which is the reference's behaviour too, and
//! why an unmount and a sync both write one.
//!
//! The pack alternates. A checkpoint is never written over the one being
//! replaced: it goes to the other of the two packs with the version raised by
//! one, so a machine that dies mid-write still has the older pack whole. That
//! is the single property that makes this filesystem recoverable, and writing
//! in place would destroy it.
//!
//! Order inside the pack matters and is not free choice: head block, payload,
//! the three data summaries, the three node summaries, then the head block
//! again as the tail. A reader locates the summaries by counting BACK from the
//! pack's end, so a pack whose length disagrees with what it wrote hands out
//! the wrong block as a journal.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::checkpoint::Pack;
use crate::flags::*;
use crate::summary::{NatEntry, SitEntry};
use crate::uapi::*;

use super::orphan;
use super::segmap;
use super::Volume;

/// Why a checkpoint is being written.
///
/// It decides two things that must agree: whether the node logs' summaries go
/// into the pack, and how long the pack therefore is. A reader locates the
/// summaries by counting BACK from the pack's end, so a flag that disagrees
/// with the length hands it the wrong block.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CpReason {
    /// An ordinary flush. The node logs' summaries stay where they are; a
    /// mount reconstructs the open ones by reading their segments.
    Sync,
    /// The volume is going away. Everything goes in the pack, which is what
    /// makes the next mount cheap and tells it the shutdown was clean.
    Umount,
}

/// Write a little-endian value into a buffer.
fn p16(b: &mut [u8], at: usize, v: u16) { b[at..at + 2].copy_from_slice(&v.to_le_bytes()); }
fn p32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
fn p64(b: &mut [u8], at: usize, v: u64) { b[at..at + 8].copy_from_slice(&v.to_le_bytes()); }

impl<S: SectorSource> Volume<S> {
    /// Make everything this mount has changed durable.
    ///
    /// A mount with nothing dirty writes nothing: a checkpoint costs the whole
    /// pack, and writing one per sync on an idle filesystem burns the medium
    /// for no state change.
    /// # C: O(dirty table blocks + pack blocks)
    /// The reason is read off the volume's own condition rather than taken
    /// from the caller: a flush taken while the closing mark stands IS the
    /// last one, and it is the mark — not the call site — that knows. A
    /// caller that had to say so would get it wrong on every path that
    /// reaches here indirectly, and the whole pack would be written as an
    /// ordinary sync, telling the next mount the shutdown was not clean.
    pub fn commit(&mut self) -> Result<(), Errno> {
        let closing = self.sbi.is_set(crate::sbflags::bits::IS_CLOSE);
        self.commit_with(if closing { CpReason::Umount } else { CpReason::Sync })
    }

    /// The same, saying why.
    /// # C: O(dirty table blocks + pack blocks)
    pub fn commit_with(&mut self, reason: CpReason) -> Result<(), Errno> {
        if !self.writable { return Ok(()); }
        let outcome = self.commit_attempt(reason);
        // A sync that could not be completed leaves the medium describing the
        // PREVIOUS state while this mount carries on believing its own, so
        // checkpointing stops and the reason is recorded. Reporting the errno
        // upwards and nothing else left the mount live and writing on top of a
        // checkpoint it had failed to place, and told the next mount nothing.
        // This is also the one path that makes `errors=` reachable from a real
        // failure rather than only from a shutdown, which forces its own
        // behaviour whatever the option says.
        //
        // Wrapping the WHOLE attempt, not only the pack write: a placement that
        // fails is just as unrecorded as a pack that fails, and the early `?`
        // returns below are exactly where the first attempt at this missed it.
        if outcome.is_err() {
            self.stop_checkpoint(crate::errrec::StopReason::MetaPage, false);
        }
        outcome
    }

    /// One attempt at the sync, reporting the first thing that would not land.
    /// # C: O(dirty table blocks + pack blocks)
    fn commit_attempt(&mut self, reason: CpReason) -> Result<(), Errno> {
        // The error record goes down FIRST, and ahead of the dirty test below.
        // A read path that found a corruption can only add to the record in
        // memory — it has no write — so this is where it reaches the medium,
        // and it must not be conditional on the checkpoint having anything of
        // its own to write: a mount whose ONLY change is a fault it found is
        // exactly the mount whose record the next mount and fsck need. Best
        // effort, because a failure to record a fault must not turn into a
        // failure of the sync that noticed it.
        let _ = self.record_errors();
        // Before the dirty test, not after: a mount whose only change is a
        // buffered write has pages to place, and placing them is what makes
        // it dirty in the sense the test means.
        self.flush_all_data_pages()?;
        // Then the nodes, and in that order: placing a data page writes an
        // address into the node that holds it, so nodes flushed first would be
        // dirty again by the time the table was written. Before the dirty test
        // for the same reason the data flush is — a mount whose only change is
        // a node has one to place, and placing it is what makes it dirty in
        // the sense the test means.
        self.flush_all_nodes()?;
        if !self.dirty { return Ok(()); }
        // Every metadata block written from here to the end of this call is
        // the checkpoint's, which is the only thing that tells it apart from
        // an ordinary summary flush. Lowered on every exit, including the
        // failing ones: a mark left standing would charge the next mount-wide
        // metadata write to a checkpoint that is not running.
        self.segstate.cp_writing = true;
        let outcome = self.commit_body(reason);
        self.segstate.cp_writing = false;
        outcome
    }

    /// # C: O(dirty table blocks + pack blocks)
    fn commit_body(&mut self, reason: CpReason) -> Result<(), Errno> {
        self.load_segments()?;
        // Accounting becomes durable with everything else it describes.
        self.flush_quotas()?;
        // AGAIN, and after the quota files: writing them is an ordinary file
        // write, so it leaves data pages and node pages behind exactly as any
        // other write does. A node still in the mapping when the table below
        // is written would have its NO-ADDRESS-YET marker recorded as the
        // node's address, which the next mount reads as a node that is not
        // there. This is the reference's own drain-before-the-table step.
        self.flush_all_data_pages()?;
        self.flush_all_nodes()?;
        let mut nat_bitmap = self.nat_bitmap.clone();
        let mut sit_bitmap = self.sit_bitmap.clone();
        let nat_journal = self.flush_nat(&mut nat_bitmap)?;
        let sit_journal = self.flush_sit(&mut sit_bitmap)?;
        // The segments held since the last checkpoint become free HERE, before
        // the pack is built: this checkpoint is the one that retires the
        // references they were being held against, and it must record the
        // free count that includes them.
        self.clear_prefree();
        let version = self.cp.version.wrapping_add(1);
        let pack = match self.cp.pack { Pack::First => Pack::Second, Pack::Second => Pack::First };
        let start = match pack {
            Pack::First => self.sb.cp_blkaddr,
            Pack::Second => self.sb.cp_blkaddr + self.sb.blks_per_seg(),
        };
        let payload = self.sb.cp_payload;
        let logs = summaries_in_pack(reason);
        // The parked inodes ride in the pack, between the payload and the
        // summaries. Both pack numbers move with them: a reader counts the
        // summaries BACK from the pack's end and the orphan region FORWARD to
        // where the summaries start, so a pack whose length or start-of-sum
        // disagrees hands one of them the other's blocks.
        let orphan_blocks = self.orphan_blocks();
        let total = orphan::block::pack_total(payload, orphan_blocks, logs);
        let start_sum = orphan::block::pack_start_sum(payload, orphan_blocks);
        let head = self.build_cp(version, total, start_sum, reason,
                                 &nat_bitmap, &sit_bitmap)?;
        self.write_block(start, &head)?;
        for i in 1..=payload { self.write_block(start + i, &vec![0u8; BLKSIZE])?; }
        self.write_orphans(start + 1 + payload)?;
        self.write_summaries(start, total, logs, &nat_journal, &sit_journal)?;
        // Everything this checkpoint refers to has now been written. On a volume
        // spread over several members, the ones that do NOT carry the pack are
        // fenced HERE, after the last of it went down and before the block that
        // makes it current: their caches must be empty, or the pack names blocks
        // a power loss never finished writing. The member that carries the pack
        // is left to the commit block below, whose own pre-flush fences it —
        // asking here as well would cost a second barrier for one guarantee.
        self.flush_device_cache()?;
        // The tail goes last, and under a durability promise rather than as an
        // ordinary write. Until it lands the pack reads as torn and the other
        // pack stays current, which is the guarantee wanted — but only if the
        // device cannot reorder it ahead of the pack it commits. Its pre-flush
        // is what forbids that, and its forced-unit-access is what makes the
        // checkpoint durable by the time this call returns rather than whenever
        // the device gets round to it.
        let promise = crate::devices::barrier::commit_block_durability(self.opts.barrier);
        self.write_block_durable(start + total - 1, &head, promise)?;
        // Its pre-flush put everything written before it on the medium, and
        // that includes every page this mount rewrote IN PLACE — so no file is
        // still owed a barrier on their account. Retired only when the promise
        // was actually made: a mount that asked for no barriers wrote this
        // block plain and fenced nothing, and forgetting the debt there would
        // leave those bytes volatile with nothing left to say so.
        if !promise.is_empty() { self.note_all_fenced(); }
        self.adopt(head, pack, payload, nat_bitmap, sit_bitmap, nat_journal, sit_journal)
    }

    /// Take the checkpoint just written as this mount's own state. # C: O(1)
    #[allow(clippy::too_many_arguments)]
    fn adopt(&mut self, head: Vec<u8>, pack: Pack, payload: u32, nat_bitmap: Vec<u8>,
             sit_bitmap: Vec<u8>, nat_journal: Vec<(u32, NatEntry)>,
             sit_journal: Vec<(u32, SitEntry)>) -> Result<(), Errno> {
        let cp = crate::checkpoint::parse(&head, pack).ok_or(Errno::Eio)?;
        self.cp_raw = crate::checkpoint::joined(&head, &vec![vec![0u8; BLKSIZE]; payload as usize]);
        self.cp = cp;
        self.nat_bitmap = nat_bitmap;
        self.sit_bitmap = sit_bitmap;
        self.nat_cache_clear();
        self.nat_journal = nat_journal;
        self.sit_journal = sit_journal;
        self.nat_dirty.clear();
        self.sit_dirty.clear();
        self.dirty = false;
        self.rf_node_block_count = 0;
        // Every entry names a directory whose blocks this checkpoint has just
        // made durable, so no file below one of them needs a checkpoint on its
        // account any more. Leaving them would make one strict removal cost a
        // checkpoint per `fsync` for the rest of the mount.
        self.ino_lists.release();
        self.sbi.checkpointed();
        // A volume mounted younger than the age threshold has no section that
        // could clear it, so the age policy started off. The checkpoint is
        // what advances the volume's recorded age, so it is also the only
        // point at which a volume can have grown into the policy — and
        // without this the mount would carry the option and never obey it.
        let (atgc, elapsed) = (self.opts.atgc, self.cp.elapsed_time);
        if self.atgc.may_reinit(atgc, elapsed) { self.atgc.enabled = true; }
        Ok(())
    }

    /// The checkpoint header block, checksum included. # C: O(BLKSIZE)
    #[allow(clippy::too_many_arguments)]
    fn build_cp(&self, version: u64, total: u32, start_sum: u32,
                reason: CpReason, nat_bitmap: &[u8], sit_bitmap: &[u8])
        -> Result<Vec<u8>, Errno> {
        let mut c = vec![0u8; BLKSIZE];
        // The summaries are written in full, so the compact form is cleared
        // and the clean-unmount mark set: both say where a reader will find
        // the journals, and a flag that disagrees sends it to another block.
        // The clean-unmount mark is set ONLY for a real unmount. Setting it on
        // every checkpoint would tell the next mount a crash never happened,
        // and there would be nothing to distinguish one that did.
        let mut flags = self.cp.flags & !(CP_COMPACT_SUM_FLAG | CP_ERROR_FLAG | CP_UMOUNT_FLAG);
        if reason == CpReason::Umount { flags |= CP_UMOUNT_FLAG; }
        // The conditions this mount is in are what the checkpoint RECORDS.
        // Reading the fsck mark back out of the word the checkpoint already
        // carries would let a clean checkpoint retire a mark the mount is
        // still raising, and the volume would forget it needs checking.
        let flags = self.sbi.cp_flags(flags);
        // Set AND cleared from the CURRENT list: a stale bit sends the next
        // mount looking for orphan blocks a pack no longer carries.
        let flags = self.orphan_flag(flags);
        p64(&mut c, CP_CHECKPOINT_VER, version);
        p64(&mut c, CP_USER_BLOCK_COUNT, self.cp.user_block_count);
        p64(&mut c, CP_VALID_BLOCK_COUNT, self.valid_block_count);
        p32(&mut c, CP_RSVD_SEGMENT_COUNT, self.cp.rsvd_segment_count);
        p32(&mut c, CP_OVERPROV_SEGMENT_COUNT, self.cp.overprov_segment_count);
        p32(&mut c, CP_FREE_SEGMENT_COUNT, self.free_segment_count());
        for (log, seg) in self.curseg.iter().enumerate() {
            let (node, i) = super::curseg::cp_slot(log);
            let (segno_at, blkoff_at) = if node {
                (CP_CUR_NODE_SEGNO + i * 4, CP_CUR_NODE_BLKOFF + i * 2)
            } else {
                (CP_CUR_DATA_SEGNO + i * 4, CP_CUR_DATA_BLKOFF + i * 2)
            };
            p32(&mut c, segno_at, seg.segno);
            p16(&mut c, blkoff_at, seg.next_blkoff);
            c[CP_ALLOC_TYPE + log] = seg.alloc_type;
        }
        p32(&mut c, CP_CKPT_FLAGS, flags);
        p32(&mut c, CP_PACK_TOTAL_BLOCK_COUNT, total);
        p32(&mut c, CP_PACK_START_SUM, start_sum);
        p32(&mut c, CP_VALID_NODE_COUNT, self.valid_node_count);
        p32(&mut c, CP_VALID_INODE_COUNT, self.valid_inode_count);
        p32(&mut c, CP_NEXT_FREE_NID, self.next_free_nid);
        p32(&mut c, CP_SIT_VER_BITMAP_BYTESIZE, sit_bitmap.len() as u32);
        p32(&mut c, CP_NAT_VER_BITMAP_BYTESIZE, nat_bitmap.len() as u32);
        // How old the volume is, not how old it was when this mount read it:
        // segment ages are measured against this, so a checkpoint that
        // carried the old value forward would restart every age at the next
        // mount and make the whole volume look the same age.
        p64(&mut c, CP_ELAPSED_TIME, self.seg_mtime_now());
        let large = flags & CP_LARGE_NAT_BITMAP_FLAG != 0;
        let base = CP_SIT_NAT_VERSION_BITMAP;
        let crc_off = if large { base } else { CP_MAX_CHKSUM_OFFSET };
        p32(&mut c, CP_CHECKSUM_OFFSET_FIELD, crc_off as u32);
        let (nat_at, sit_at) = if large {
            (base + 4, base + 4 + nat_bitmap.len())
        } else {
            (base + sit_bitmap.len(), base)
        };
        if nat_at + nat_bitmap.len() > BLKSIZE || sit_at + sit_bitmap.len() > BLKSIZE {
            return Err(Errno::Enospc);
        }
        c[nat_at..nat_at + nat_bitmap.len()].copy_from_slice(nat_bitmap);
        c[sit_at..sit_at + sit_bitmap.len()].copy_from_slice(sit_bitmap);
        let crc = crate::checksum::crc32(&c[..crc_off]);
        p32(&mut c, crc_off, crc);
        Ok(c)
    }

    /// The six summary blocks, with the two journals ridden along.
    /// # C: O(6 blocks)
    fn write_summaries(&mut self, start: u32, total: u32, logs: usize,
                       nat: &[(u32, NatEntry)], sit: &[(u32, SitEntry)]) -> Result<(), Errno> {
        for log in 0..logs {
            let node = log >= NR_CURSEG_DATA_TYPE;
            self.curseg[log].seal(node);
            let mut block = self.curseg[log].sum.clone();
            if log == CURSEG_HOT_DATA { write_nat_journal(&mut block, nat); }
            if log == CURSEG_COLD_DATA { write_sit_journal(&mut block, sit); }
            if log == CURSEG_HOT_DATA || log == CURSEG_COLD_DATA {
                // The footer sits past the journal, so resealing after the
                // journal goes in is what keeps the two consistent.
                let at = BLKSIZE - SUM_FOOTER_SIZE;
                let crc = crate::checksum::crc32(&block[..at]);
                block[at + 1..at + 5].copy_from_slice(&crc.to_le_bytes());
            }
            let addr = crate::summary::normal_sum_addr(start, total, logs, log);
            self.write_block(addr, &block)?;
        }
        // A node log whose summary does not go in the pack still has to be
        // recoverable, so it goes to the summary area instead — otherwise the
        // segment's ownership record is simply lost.
        for log in logs..NR_CURSEG_PERSIST_TYPE {
            let segno = self.curseg[log].segno;
            if segno == NULL_SEGNO { continue; }
            self.curseg[log].seal(true);
            let block = self.curseg[log].sum.clone();
            self.write_block(sum_block_addr(self.sb.ssa_blkaddr, segno), &block)?;
        }
        self.save_pinned_curseg()?;
        Ok(())
    }

    /// Put the pinned log's ownership record where a mount can find it.
    ///
    /// The pinned log is in no checkpoint, so the pack cannot carry its
    /// summary and the next mount will not reopen it. A segment it filled must
    /// therefore leave its summary in the summary area or the section becomes
    /// uncleanable; a section it opened and never used is handed back instead,
    /// because holding it across a checkpoint nothing records would strand it.
    /// # C: O(1 block)
    fn save_pinned_curseg(&mut self) -> Result<(), Errno> {
        let log = crate::uapi::CURSEG_COLD_DATA_PINNED;
        let segno = self.curseg[log].segno;
        if segno == NULL_SEGNO { return Ok(()); }
        if self.seg_valid(segno) > 0 {
            self.curseg[log].seal(false);
            let block = self.curseg[log].sum.clone();
            self.write_block(sum_block_addr(self.sb.ssa_blkaddr, segno), &block)?;
        } else {
            self.retire_segment(segno);
            self.curseg[log] = crate::volume::curseg::Curseg::empty();
        }
        Ok(())
    }

    /// Push the changed node-table entries: journal what fits, rewrite the
    /// rest into the OTHER copy of their table block.
    ///
    /// The bit flip is the commit. A block rewritten without flipping its bit
    /// is written where nothing will read it, and every entry in it silently
    /// keeps its old value.
    /// # C: O(dirty table blocks)
    fn flush_nat(&mut self, bitmap: &mut [u8]) -> Result<Vec<(u32, NatEntry)>, Errno> {
        let mut journal: Vec<(u32, NatEntry)> = Vec::new();
        let mut groups: Vec<(u32, Vec<(u32, NatEntry)>)> = Vec::new();
        for (&nid, e) in self.nat_dirty.iter() {
            // An id claimed but never written names no block; recording it
            // would hand a reader an address that was never allocated.
            if e.block_addr == NEW_ADDR { continue; }
            let (block_off, _) = crate::nat::locate(nid);
            match groups.iter_mut().find(|(o, _)| *o == block_off) {
                Some((_, v)) => v.push((nid, *e)),
                None => groups.push((block_off, alloc::vec![(nid, *e)])),
            }
        }
        // Carry forward journalled entries this mount did not change; dropping
        // them would revert whatever the previous checkpoint parked there.
        for (nid, e) in self.nat_journal.clone() {
            if !self.nat_dirty.contains_key(&nid) { journal.push((nid, e)); }
        }
        for (block_off, entries) in groups {
            if journal.len() + entries.len() <= NAT_JOURNAL_ENTRIES {
                for (nid, e) in entries { journal.retain(|(n, _)| *n != nid); journal.push((nid, e)); }
                continue;
            }
            journal.retain(|(n, _)| crate::nat::locate(*n).0 != block_off);
            self.rewrite_nat_block(block_off, &entries, bitmap)?;
        }
        Ok(journal)
    }

    /// Rewrite one node-table block into its other copy. # C: O(BLKSIZE)
    fn rewrite_nat_block(&mut self, block_off: u32, entries: &[(u32, NatEntry)],
                         bitmap: &mut [u8]) -> Result<(), Errno> {
        let per_seg = self.sb.blks_per_seg();
        let base = self.sb.nat_blkaddr + (block_off << 1) - (block_off & (per_seg - 1));
        let was_second = crate::checkpoint::test_bit(&self.nat_bitmap, block_off as usize);
        let (cur, other) =
            if was_second { (base + per_seg, base) } else { (base, base + per_seg) };
        let mut block = self.read_block(cur)?;
        for (nid, e) in entries {
            let (_, off) = crate::nat::locate(*nid);
            block[off + NAT_VERSION] = e.version;
            p32(&mut block, off + NAT_INO, e.ino);
            p32(&mut block, off + NAT_BLOCK_ADDR, e.block_addr);
        }
        self.write_block(other, &block)?;
        let byte = block_off as usize / 8;
        if byte < bitmap.len() { bitmap[byte] ^= 1 << (block_off % 8); }
        Ok(())
    }

    /// The same for the segment table. # C: O(dirty table blocks)
    fn flush_sit(&mut self, bitmap: &mut [u8]) -> Result<Vec<(u32, SitEntry)>, Errno> {
        let dirty = self.dirty_segments();
        let mut journal: Vec<(u32, SitEntry)> = Vec::new();
        for (segno, e) in self.sit_journal.clone() {
            if !self.sit_dirty.contains(&segno) { journal.push((segno, e)); }
        }
        let mut groups: Vec<(u32, Vec<(u32, SitEntry)>)> = Vec::new();
        for (segno, e) in dirty {
            let (block_off, _) = crate::sit::locate(segno);
            match groups.iter_mut().find(|(o, _)| *o == block_off) {
                Some((_, v)) => v.push((segno, e)),
                None => groups.push((block_off, alloc::vec![(segno, e)])),
            }
        }
        for (block_off, entries) in groups {
            if journal.len() + entries.len() <= SIT_JOURNAL_ENTRIES {
                for (segno, e) in entries {
                    journal.retain(|(s, _)| *s != segno);
                    journal.push((segno, e));
                }
                continue;
            }
            journal.retain(|(s, _)| crate::sit::locate(*s).0 != block_off);
            self.rewrite_sit_block(block_off, &entries, bitmap)?;
        }
        Ok(journal)
    }

    /// Rewrite one segment-table block into its other copy. # C: O(BLKSIZE)
    fn rewrite_sit_block(&mut self, block_off: u32, entries: &[(u32, SitEntry)],
                         bitmap: &mut [u8]) -> Result<(), Errno> {
        let blocks = crate::sit::area_blocks(self.sb.segment_count_sit, self.sb.blks_per_seg());
        let base = self.sb.sit_blkaddr + block_off;
        let was_second = crate::checkpoint::test_bit(&self.sit_bitmap, block_off as usize);
        let (cur, other) = if was_second { (base + blocks, base) } else { (base, base + blocks) };
        let mut block = self.read_block(cur)?;
        let patch = segmap::sit_block(entries);
        for (segno, _) in entries {
            let (_, off) = crate::sit::locate(*segno);
            block[off..off + SIT_ENTRY_SIZE].copy_from_slice(&patch[off..off + SIT_ENTRY_SIZE]);
        }
        self.write_block(other, &block)?;
        let byte = block_off as usize / 8;
        if byte < bitmap.len() { bitmap[byte] ^= 1 << (block_off % 8); }
        Ok(())
    }
}

/// How many logs' summaries a pack of this kind carries. # C: O(1)
pub fn summaries_in_pack(reason: CpReason) -> usize {
    match reason {
        CpReason::Umount => NR_CURSEG_PERSIST_TYPE,
        CpReason::Sync => NR_CURSEG_DATA_TYPE,
    }
}

/// Lay a node-table journal into a summary block. # C: O(entries)
pub fn write_nat_journal(block: &mut [u8], entries: &[(u32, NatEntry)]) {
    let off = crate::summary::at::NORMAL;
    let n = entries.len().min(NAT_JOURNAL_ENTRIES);
    p16(block, off, n as u16);
    for (i, (nid, e)) in entries.iter().take(n).enumerate() {
        let at = off + 2 + i * NAT_JOURNAL_ENTRY_SIZE;
        p32(block, at, *nid);
        block[at + 4 + NAT_VERSION] = e.version;
        p32(block, at + 4 + NAT_INO, e.ino);
        p32(block, at + 4 + NAT_BLOCK_ADDR, e.block_addr);
    }
}

/// Lay a segment-table journal into a summary block. # C: O(entries)
pub fn write_sit_journal(block: &mut [u8], entries: &[(u32, SitEntry)]) {
    let off = crate::summary::at::NORMAL;
    let n = entries.len().min(SIT_JOURNAL_ENTRIES);
    p16(block, off, n as u16);
    for (i, (segno, e)) in entries.iter().take(n).enumerate() {
        let at = off + 2 + i * SIT_JOURNAL_ENTRY_SIZE;
        p32(block, at, *segno);
        p16(block, at + 4 + SIT_VBLOCKS, e.vblocks);
        block[at + 4 + SIT_VALID_MAP..at + 4 + SIT_VALID_MAP + SIT_VBLOCK_MAP_SIZE]
            .copy_from_slice(&e.valid_map);
        p64(block, at + 4 + SIT_MTIME, e.mtime);
    }
}

#[cfg(test)]
#[path = "../tests/commitv.rs"]
mod tests;
