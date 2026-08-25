use super::*;

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
        self.search_victim_with_valid_thresh(search, skip, 100)
    }

    /// The foreground/one-time search with Linux's live-ratio ceiling. # C: O(main segments)
    pub fn search_victim_with_valid_thresh(&self, search: Search, skip: &[u32], ratio: u32)
        -> Option<Found> {
        let table = self.seg_table();
        let units = victim::units(&table, self.sb.blks_per_seg() as u16, self.sb.segs_per_sec);
        victim::pick_unit_with_valid_thresh(&units, self.sb.blks_per_seg() as u16,
                                            self.sb.segs_per_sec, search, skip, ratio)
    }

    /// The section worth cleaning next for a caller that needs space now.
    /// # C: O(main segments)
    pub fn pick_victim(&self, policy: Policy, skip: &[u32]) -> Option<u32> {
        self.search_victim_with_valid_thresh(Search::foreground(policy), skip,
                                             self.gc_valid_thresh_ratio)
            .map(|f| f.segno)
    }
}
