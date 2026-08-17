//! Cleaning a section, and cleaning until there is room again.
//!
//! Without this the volume runs out of space while reporting free blocks. Every
//! write is out of place, so a file rewritten in place leaves its old block
//! dead where it lies; the segment holding it is neither free — a free segment
//! has nothing live in it — nor usable by the append allocator, which only ever
//! opens empty segments. The dead blocks are real free space that nothing can
//! reach until something moves the survivors out and hands the segment back.
//!
//! Handing it back takes a CHECKPOINT. A cleaned segment is prefree, not free:
//! the checkpoint on the medium still names the blocks that were in it, so the
//! allocator may not have it until one that does not lands. That is why this
//! module writes a checkpoint when cleaning alone has not produced usable
//! space — without it the cleaner would free segment after segment and the
//! allocation that called it would still fail.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::stats::counters::gc_mode;
use crate::uapi::*;

use super::live;
use super::victim::{self, Found, Policy, Search, SegInfo, PERCENT};
use crate::volume::Volume;

/// The share of the volume that may sit prefree before a checkpoint is worth
/// taking just to hand it back.
pub const RECLAIM_PREFREE_PERCENT: u32 = 5;
/// The point past which that share stops growing: beyond it a checkpoint is
/// due on volume in any case, and the share alone would defer one forever.
pub const MAX_RECLAIM_PREFREE_SEGMENTS: u32 = 4096;

impl<S: SectorSource> Volume<S> {
    /// The segment table as victim selection sees it. # C: O(main segments)
    pub(crate) fn seg_table(&self) -> Vec<SegInfo> {
        self.segments()
            .iter()
            .enumerate()
            .map(|(i, e)| SegInfo {
                segno: i as u32,
                live: e.valid_blocks(),
                mtime: e.mtime,
                current: self.is_current(i as u32),
            })
            .collect()
    }

    /// The section worth cleaning next by AGE, or `None` when the policy is
    /// off or no section is old enough.
    ///
    /// The candidate set is rebuilt per search rather than kept: a section's
    /// age is its distance from the newest one seen, so a set carried across
    /// searches would cost today's candidates against yesterday's span.
    /// # C: O(main segments + min(candidates, the search bound))
    pub fn search_victim_by_age(&mut self, skip: &[u32]) -> Option<Found> {
        if !self.atgc.enabled { return None; }
        let per_sec = self.sb.segs_per_sec.max(1);
        let per_seg = self.sb.blks_per_seg() as u16;
        let table = self.seg_table();
        let units = victim::units(&table, per_seg, per_sec);
        let cp_disabled = self.opts.checkpoint_disabled;
        self.atgc.begin();
        for u in units.iter() {
            if !victim::unit_eligible(u) || skip.contains(&u.first) { continue; }
            self.atgc.add_candidate(u.first, u.mtime, u.live, cp_disabled);
        }
        let live_of = |first: u32| units.iter().find(|u| u.first == first).map_or(0, |u| u.live);
        let sec_blocks = u32::from(per_seg) * per_sec;
        let pick = self.atgc.lookup_victim(sec_blocks, &live_of);
        self.atgc.release();
        let total = units.len() as u32 * per_sec;
        pick.map(|p| Found { segno: p.segno, cursor: (p.segno + per_sec) % total.max(1) })
    }

    /// The section worth cleaning next under `search`, and where the search
    /// after it should resume. # C: O(main segments)
    pub fn search_victim(&self, search: Search, skip: &[u32]) -> Option<Found> {
        let table = self.seg_table();
        let units = victim::units(&table, self.sb.blks_per_seg() as u16, self.sb.segs_per_sec);
        victim::pick_unit(&units, self.sb.blks_per_seg() as u16, self.sb.segs_per_sec,
                          search, skip)
    }

    /// The section worth cleaning next for a caller that needs space now.
    /// # C: O(main segments)
    pub fn pick_victim(&self, policy: Policy, skip: &[u32]) -> Option<u32> {
        self.search_victim(Search::foreground(policy), skip).map(|f| f.segno)
    }

    /// Clean `segno`: move out everything still live in it.
    ///
    /// Returns the blocks moved. A segment can come back with blocks still in
    /// it — a block the table calls live that no owner claims is left exactly
    /// where it is, because moving it would write an address into a file that
    /// does not want one.
    /// # C: O(blocks per segment) blocks read and rewritten
    pub fn gc_segment(&mut self, segno: u32) -> Result<u32, Errno> {
        self.writable_or_err()?;
        // The cleaner moves blocks by ADDRESS. A page written but not yet
        // placed has none, and the move would drop it from the mapping while
        // relocating the block it no longer describes — so every pending
        // write goes down first, whatever file it belongs to — nodes as well
        // as data, because a node the cleaner is about to relocate that is
        // still only in the node mapping has no address to move.
        self.sync_data()?;
        self.load_segments()?;
        if segno >= self.sb.segment_count_main { return Err(Errno::Einval); }
        // A log is still appending here; its own summary entries are in memory
        // and the block after the one being read is about to be handed out.
        if self.is_current(segno) { return Err(Errno::Ebusy); }
        let per_seg = self.sb.blks_per_seg();
        let sum = self.read_block(sum_block_addr(self.sb.ssa_blkaddr, segno))?;
        let nodes = live::holds_nodes(&sum);
        let base = self.sb.main_blkaddr + segno * per_seg;
        let mut moved = 0u32;
        let mut stale: Vec<u32> = Vec::new();
        // Everything written from here carries the victim's age rather than
        // this instant's: the data is exactly as old as it was, and a cleaner
        // that made its own output look freshly written would hide it from
        // the policy that is trying to find old data.
        self.segstate.gc_moving = true;
        self.segstate.gc_src_mtime = self.seg_mtime(segno);
        let outcome = self.move_live_blocks(segno, base, per_seg, nodes, &sum, &mut stale,
                                            &mut moved)
            // Only now: while any of these bits stood the segment could not be
            // opened by a log, which is what kept the copies above reading the
            // blocks they meant to read. Inside the flag, because emptying the
            // victim is part of the migration and not a write either.
            .and_then(|()| stale.into_iter().try_for_each(|a| self.release_block(a)));
        self.segstate.gc_moving = false;
        outcome?;
        // One segment cleaned, charged to the policy this pass is running
        // under. Raised here rather than where the pass ends because a pass
        // cleans several segments and the figure is per segment.
        self.counters.borrow_mut().add_reclaimed_segs(self.segstate.gc_pass_mode, 1);
        Ok(moved)
    }

    /// Move every live block of one segment out of it. # C: O(blocks)
    #[allow(clippy::too_many_arguments)]
    fn move_live_blocks(&mut self, segno: u32, base: u32, per_seg: u32, nodes: bool,
                        sum: &[u8], stale: &mut Vec<u32>, moved: &mut u32)
        -> Result<(), Errno> {
        for off in 0..per_seg as usize {
            let addr = base + off as u32;
            let bit = self.segments().get(segno as usize).is_some_and(|e| e.is_valid(off));
            let Some(s) = live::entry(sum, off) else { continue };
            let owner = if nodes { self.node_addr(s.nid).ok() } else { self.owner_addr(&s) };
            if !live::alive(bit, &s, owner, addr) { continue; }
            // A pinned block stays where it is, whatever the cleaner wants:
            // something outside the filesystem is holding its address, and
            // moving it would leave that holder reading someone else's data.
            // The collision is charged to the file that caused it, and a file
            // that has cost too many of them loses its pin.
            if !nodes {
                if let Some(owner_ino) = self.pinned_owner_ino(&s)? {
                    let _ = self.pin_file_control(owner_ino, true);
                    continue;
                }
            }
            if nodes { self.migrate_node(s.nid)?; } else { self.migrate_data(addr, &s)?; stale.push(addr); }
            *moved += 1;
        }
        Ok(())
    }

    /// Clean a whole section, which is the unit the allocator hands out.
    ///
    /// A section half cleaned is a section still in use, so the space cleaning
    /// it cost buys nothing until every segment in it is empty.
    /// # C: O(blocks per section)
    pub fn gc_section(&mut self, first: u32) -> Result<u32, Errno> {
        self.load_segments()?;
        let per_sec = self.sb.segs_per_sec.max(1);
        // The section's summary blocks, fetched before the first segment is
        // cleaned: they are consecutive, and every segment below reads one.
        self.ra_meta_pages(crate::uapi::sum_block_addr(self.sb.ssa_blkaddr, first), per_sec,
                           crate::volume::readahead::RaMeta::Ssa);
        let mut moved = 0u32;
        for segno in first..(first + per_sec).min(self.sb.segment_count_main) {
            // A log inside the section stops the section being reclaimable,
            // but the segments beside it are still worth emptying.
            if self.is_current(segno) { continue; }
            moved += self.gc_segment(segno)?;
        }
        Ok(moved)
    }

    /// Clean the single best victim. # C: O(blocks per section)
    pub fn gc_one_segment(&mut self) -> Result<Option<u32>, Errno> {
        self.gc_one_segment_as(Policy::Greedy, gc_mode::NORMAL)
    }

    /// The same, under a stated cost and charged to a stated policy.
    /// # C: O(blocks per section)
    pub fn gc_one_segment_as(&mut self, policy: Policy, mode: usize)
        -> Result<Option<u32>, Errno> {
        self.writable_or_err()?;
        self.load_segments()?;
        let Some(segno) = self.pick_victim(policy, &[]) else { return Ok(None) };
        self.segstate.gc_pass_mode = mode;
        let outcome = self.gc_section(segno);
        self.segstate.gc_pass_mode = gc_mode::NORMAL;
        outcome?;
        Ok(Some(segno))
    }

    /// Clean until `target` segments are free, or until nothing is worth
    /// cleaning. Returns the sections emptied.
    /// # C: O(sections cleaned * blocks per section)
    pub fn collect(&mut self, target: u32) -> Result<u32, Errno> {
        self.collect_with(Policy::Greedy, target)
    }

    /// The same, under a stated policy.
    ///
    /// Re-entry is refused rather than queued. The checkpoint this takes to
    /// reclaim what it cleaned can itself allocate, and an allocation that
    /// runs short calls the cleaner — a loop that would clean inside its own
    /// checkpoint inside its own clean.
    /// # C: O(sections cleaned * blocks per section)
    pub fn collect_with(&mut self, policy: Policy, target: u32) -> Result<u32, Errno> {
        self.collect_as(policy, target, gc_mode::NORMAL)
    }

    /// The same, charged to the policy the caller is running under.
    ///
    /// The mode is a property of the PASS, not of the volume: the user's knob
    /// turns the cleaner thread's mode, and the thread states it here for the
    /// figures rather than the volume keeping a second copy that could
    /// disagree with the one being obeyed. Anything that is not the cleaner
    /// thread cleans under the ordinary policy and is counted as such.
    /// # C: O(sections cleaned * blocks per section)
    pub fn collect_as(&mut self, policy: Policy, target: u32, mode: usize) -> Result<u32, Errno> {
        self.writable_or_err()?;
        if self.segstate.gc_running { return Ok(0); }
        self.segstate.gc_running = true;
        self.segstate.gc_pass_mode = mode;
        let outcome = self.collect_inner(policy, target);
        self.segstate.gc_pass_mode = gc_mode::NORMAL;
        self.segstate.gc_running = false;
        outcome
    }

    /// Clean, then checkpoint what cleaning produced, then clean again.
    ///
    /// A victim is never tried twice in one call. One that would not empty —
    /// because a block in it is live by the table and disowned by every node —
    /// would otherwise be chosen again on the next pass and the cleaner would
    /// never stop.
    /// # C: O(sections cleaned * blocks per section)
    fn collect_inner(&mut self, policy: Policy, target: u32) -> Result<u32, Errno> {
        self.load_segments()?;
        let mut skip: Vec<u32> = Vec::new();
        let mut freed = 0u32;
        // Two rounds at most: clean, retire what was cleaned, clean again.
        // A third would find the same sections the first two rejected.
        for round in 0..2 {
            freed += self.clean_round(policy, target, &mut skip)?;
            if self.free_segment_count() >= target { break; }
            // Everything cleaned so far is prefree and therefore useless to
            // the caller. Only a checkpoint makes it space.
            if round == 0 && self.prefree_count() > 0 { self.commit()?; }
        }
        Ok(freed)
    }

    /// One pass of cleaning: victims until the target is met or none is left.
    /// # C: O(sections cleaned * blocks per section)
    fn clean_round(&mut self, policy: Policy, target: u32, skip: &mut Vec<u32>)
        -> Result<u32, Errno> {
        let mut freed = 0u32;
        while self.free_segment_count() < target {
            // What an ahead-of-demand search already costed comes first. A
            // section is in that set because a search found it the cheapest
            // thing to empty, so a caller that needs space now takes it
            // without costing the table again — and taking it is also what
            // stops the next ahead-of-demand pass from skipping it forever.
            let segno = match self.take_bg_victim() {
                Some(s) if !skip.contains(&s) => s,
                _ => {
                    let search =
                        Search { offset: self.segstate.gc_cursor, ..Search::foreground(policy) };
                    let Some(found) = self.search_victim(search, skip) else { break };
                    self.segstate.gc_cursor = found.cursor;
                    // A section this caller is about to empty is no longer
                    // worth remembering as a candidate.
                    self.clear_victim_section(found.segno);
                    found.segno
                }
            };
            self.gc_section(segno)?;
            if self.section_valid(segno) == 0 { freed += 1; }
            skip.push(segno);
        }
        Ok(freed)
    }

    /// Live blocks across the section `first` starts. # C: O(segments per section)
    pub(crate) fn section_valid(&self, first: u32) -> u32 {
        let per_sec = self.sb.segs_per_sec.max(1);
        (first..(first + per_sec).min(self.sb.segment_count_main))
            .map(|s| u32::from(self.seg_valid(s)))
            .sum()
    }

    /// Clean ahead of demand: one bounded, resuming pass under cost-benefit.
    ///
    /// The policy differs from the foreground one deliberately. A caller that
    /// needs space now wants the segment that costs least to empty; a caller
    /// with time wants the one whose blocks are least likely to die on their
    /// own, which is the old one.
    /// # C: O(min(sections, max search) + blocks per section)
    pub fn gc_background(&mut self) -> Result<Option<u32>, Errno> {
        self.gc_background_as(Policy::CostBenefit, gc_mode::NORMAL)
    }

    /// Clean ahead of demand, choosing the victim by AGE.
    ///
    /// Falls back to the ordinary ahead-of-demand pass when the age policy is
    /// off or has no candidate old enough. Falling back rather than doing
    /// nothing is the point: a volume whose sections are all young still needs
    /// cleaning, and a cleaner that declined until something aged would let it
    /// run out of space while reporting that it had nothing to do.
    /// # C: O(main segments + blocks per section)
    pub fn gc_background_age(&mut self, mode: usize) -> Result<Option<u32>, Errno> {
        self.writable_or_err()?;
        if self.segstate.gc_running { return Ok(None); }
        self.load_segments()?;
        let skip = self.retained_victim_segs();
        let Some(found) = self.search_victim_by_age(&skip) else {
            return self.gc_background_as(Policy::CostBenefit, mode);
        };
        self.segstate.gc_cursor = found.cursor;
        self.mark_victim_section(found.segno);
        self.segstate.gc_running = true;
        self.segstate.gc_pass_mode = mode;
        self.segstate.gc_atgc_log = self.atgc.enabled;
        let outcome = self.gc_section(found.segno);
        self.segstate.gc_atgc_log = false;
        self.segstate.gc_pass_mode = gc_mode::NORMAL;
        self.segstate.gc_running = false;
        outcome?;
        Ok(Some(found.segno))
    }

    /// The same, under a stated cost and charged to a stated policy.
    /// # C: O(min(sections, max search) + blocks per section)
    pub fn gc_background_as(&mut self, policy: Policy, mode: usize)
        -> Result<Option<u32>, Errno> {
        self.writable_or_err()?;
        if self.segstate.gc_running { return Ok(None); }
        self.load_segments()?;
        let search = Search::background(policy, self.segstate.gc_cursor);
        // What an earlier ahead-of-demand pass already chose is passed over.
        // This search is BOUNDED, so without the exclusion it would settle on
        // the same cheapest section every round and the rest of the volume
        // would never be costed at all.
        let skip = self.retained_victim_segs();
        let Some(found) = self.search_victim(search, &skip) else { return Ok(None) };
        self.segstate.gc_cursor = found.cursor;
        self.mark_victim_section(found.segno);
        self.segstate.gc_running = true;
        self.segstate.gc_pass_mode = mode;
        self.segstate.gc_atgc_log = self.atgc.enabled;
        let outcome = self.gc_section(found.segno);
        self.segstate.gc_atgc_log = false;
        self.segstate.gc_pass_mode = gc_mode::NORMAL;
        self.segstate.gc_running = false;
        outcome?;
        Ok(Some(found.segno))
    }

    /// Whether a cleaning pass is already under way. # C: O(1)
    pub fn gc_is_running(&self) -> bool { self.segstate.gc_running }

    /// Whether the volume holds enough dead space, and little enough free
    /// space, for background cleaning to be worth the writes it costs.
    ///
    /// Both halves are needed and the second is the one that is easy to drop.
    /// Dead space alone is not a reason to clean: a volume with room to write
    /// can go on writing, and the blocks a pass would move may be invalidated
    /// by the next write anyway — which would make the cleaner's copies pure
    /// loss, paid in exactly the writes flash has a finite number of.
    /// # C: O(main segments)
    pub fn worth_cleaning(&self) -> bool {
        let per_seg = u64::from(self.sb.blks_per_seg());
        crate::bg::gc::has_enough_invalid_blocks(
            u64::from(self.cp.user_block_count),
            self.valid_block_count,
            u64::from(self.free_segment_count()) * per_seg,
            u64::from(self.cp.overprov_segment_count) * per_seg,
        )
    }

    /// Whether enough segments are waiting on a checkpoint to be worth one.
    ///
    /// The threshold is a share of the volume rather than a count: on a small
    /// volume a handful of held segments is most of the free space, and on a
    /// large one it is noise not worth a checkpoint.
    /// # C: O(1)
    pub fn excess_prefree(&self) -> bool {
        let share = self.sb.segment_count_main * RECLAIM_PREFREE_PERCENT / PERCENT as u32;
        self.prefree_count() > share.min(MAX_RECLAIM_PREFREE_SEGMENTS)
    }
}
