//! The sections an ahead-of-demand search has already chosen.
//!
//! Kept BETWEEN searches, which is the whole point. An ahead-of-demand search
//! is bounded and resumes, so without a memory of what it picked it would
//! settle on the same cheapest section every round and the rest of the volume
//! would never be scanned. A section is struck off the moment it stops being
//! worth remembering: when a caller takes it, and when it empties on its own.
//!
//! The set is also the fastest answer a caller that needs space NOW can get. A
//! section is in it because a search costed it and found it the cheapest thing
//! to empty, so a blocked allocation asks here before costing anything itself —
//! the work is already done, and the only thing left to check is that no log
//! has since opened inside it.
//!
//! Nothing here reaches the medium and nothing here is written to it. The set
//! is empty at mount by construction: it records what THIS mount's cleaner has
//! looked at, and a fresh mount has looked at nothing.

use alloc::vec::Vec;

use sectors::SectorSource;

use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// How many sections the volume has, by the same division the allocator
    /// hands them out in. # C: O(1)
    pub(crate) fn section_count(&self) -> u32 {
        let per_sec = self.sb.segs_per_sec.max(1);
        self.sb.segment_count_main.div_ceil(per_sec)
    }

    /// The section a segment belongs to. # C: O(1)
    pub(crate) fn secno_of_seg(&self, segno: u32) -> u32 { segno / self.sb.segs_per_sec.max(1) }

    /// The first segment of a section, which is what a cleaner cleans from.
    /// # C: O(1)
    pub(crate) fn first_seg_of_sec(&self, secno: u32) -> u32 { secno * self.sb.segs_per_sec.max(1) }

    /// Whether an ahead-of-demand search has chosen this section and nothing
    /// has taken it yet. # C: O(log N)
    pub fn victim_section_marked(&self, secno: u32) -> bool {
        self.segstate.victim_secs.contains(&secno)
    }

    /// Every section so chosen, lowest first. # C: O(N marked)
    pub fn victim_sections(&self) -> Vec<u32> {
        self.segstate.victim_secs.iter().copied().collect()
    }

    /// Remember that a search chose the section `segno` starts. # C: O(log N)
    pub(crate) fn mark_victim_section(&mut self, segno: u32) {
        let secno = self.secno_of_seg(segno);
        self.segstate.victim_secs.insert(secno);
    }

    /// Forget the section `segno` belongs to. # C: O(log N)
    pub(crate) fn clear_victim_section(&mut self, segno: u32) {
        let secno = self.secno_of_seg(segno);
        self.segstate.victim_secs.remove(&secno);
    }

    /// The remembered sections, as the first segment of each — the form a
    /// search takes its exclusions in, so one bounded pass cannot keep
    /// choosing what the last one chose. # C: O(N marked)
    pub(crate) fn retained_victim_segs(&self) -> Vec<u32> {
        self.segstate.victim_secs.iter().map(|&s| self.first_seg_of_sec(s)).collect()
    }

    /// Take a section a previous ahead-of-demand search chose, for a caller
    /// that needs space now.
    ///
    /// A section with a log open inside it is passed over and LEFT in the set:
    /// the log will move on, and the costing that put it there is still valid
    /// afterwards. Anything taken is struck off, because a caller is about to
    /// clean it and a second caller taking the same section would clean an
    /// empty one.
    /// # C: O(N marked * segments per section)
    pub(crate) fn take_bg_victim(&mut self) -> Option<u32> {
        let per_sec = self.sb.segs_per_sec.max(1);
        let pick = self.victim_sections().into_iter().find(|&secno| {
            let first = self.first_seg_of_sec(secno);
            let end = (first + per_sec).min(self.sb.segment_count_main);
            first < end && !(first..end).any(|s| self.is_current(s))
        })?;
        self.segstate.victim_secs.remove(&pick);
        Some(self.first_seg_of_sec(pick))
    }
}
