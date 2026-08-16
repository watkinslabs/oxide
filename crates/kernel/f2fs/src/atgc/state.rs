//! What age-threshold cleaning is tuned by, and the candidates it collects.
//!
//! The cleaner's other two costs weigh a section by how empty it is, with age
//! as at most a tiebreaker. This one inverts that: the section worth cleaning
//! is the OLD one, because data that has survived a long time is unlikely to
//! be invalidated on its own, and copying it buys space that stays bought.
//! Copying a young section instead spends writes on blocks that were about to
//! die anyway.
//!
//! That only works if young sections are excluded outright rather than merely
//! costed badly, which is what the age THRESHOLD is: a section whose age is
//! under it never becomes a candidate at all, whatever its occupancy. Without
//! the exclusion an almost-empty young section wins on the emptiness half of
//! the cost and the policy degenerates into the greedy one it was meant to
//! differ from.
//!
//! Candidates are collected during the table walk and costed afterwards,
//! because the cost needs the span of ages the walk is still discovering: a
//! section's age is its distance from the NEWEST candidate, and that is not
//! known until the last one has been seen.

use alloc::collections::BTreeSet;

use super::limits::{DEFAULT_ACCURACY_CLASS, DEF_AGE_THRESHOLD, DEF_AGE_WEIGHT,
                    DEF_CANDIDATE_RATIO, DEF_MAX_CANDIDATE_COUNT, INVALID_MTIME};
use crate::volume::gc::victim::PERCENT;

/// Everything age-threshold cleaning is tuned by, plus the candidates the
/// search in progress has collected.
///
/// The four tunables are public because they are the sysfs controls; the
/// candidate set and the span are not, because their invariants — the span
/// covers exactly the entries in the set, and the newest end never rewinds —
/// are what the cost arithmetic rests on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Atgc {
    /// Whether this mount will choose victims by age at all.
    pub enabled: bool,
    /// Share of the collected candidates one search costs, in percent.
    pub candidate_ratio: u32,
    /// Candidates one search costs regardless of that share.
    pub max_candidate_count: u32,
    /// How much of the cost is age rather than emptiness, in percent.
    pub age_weight: u32,
    /// Age a section must reach before it may be a candidate.
    pub age_threshold: u64,
    /// Candidates, oldest first.
    ///
    /// Ordered by age and then by segment number. The segment number is in
    /// the key so that two sections written in the same second are both
    /// kept — a set keyed on age alone would silently drop one — and so the
    /// order among them is decided by the volume rather than by the order the
    /// table walk happened to reach them.
    pub(super) tree: BTreeSet<(u64, u32)>,
    /// The oldest candidate this search has seen.
    pub(super) dirty_min_mtime: u64,
    /// The newest candidate this MOUNT has seen.
    ///
    /// Deliberately not reset per search, unlike the oldest end. Age is
    /// measured from the newest thing the volume has ever offered, so a
    /// search that happens to look at only old sections must not conclude
    /// that the oldest of them is young.
    pub(super) dirty_max_mtime: u64,
}

impl Default for Atgc {
    fn default() -> Self { Self::new() }
}

impl Atgc {
    /// A mount that has not yet decided anything. # C: O(1)
    pub fn new() -> Self {
        Self {
            enabled: false,
            candidate_ratio: DEF_CANDIDATE_RATIO,
            max_candidate_count: DEF_MAX_CANDIDATE_COUNT,
            age_weight: DEF_AGE_WEIGHT,
            age_threshold: DEF_AGE_THRESHOLD,
            tree: BTreeSet::new(),
            dirty_min_mtime: u64::MAX,
            dirty_max_mtime: 0,
        }
    }

    /// Turn age-threshold cleaning on if the mount asked for it and the
    /// volume is old enough to have ages worth comparing.
    ///
    /// The bound here is the FORMAT'S threshold, not the tuned one: at mount
    /// nothing has been tuned yet, and a volume younger than one threshold
    /// has no section that could clear it, so the policy would collect no
    /// candidate on every pass and quietly do nothing.
    /// # C: O(1)
    pub fn enable_at_mount(&mut self, opt_atgc: bool, elapsed_time: u64) {
        if opt_atgc && elapsed_time >= DEF_AGE_THRESHOLD { self.enabled = true; }
    }

    /// Whether a mount that started too young has now aged into it.
    ///
    /// Measured against the TUNED threshold rather than the format's, because
    /// by now a tool may have lowered it — which is exactly how a volume is
    /// asked to start ageing sooner than a week.
    /// # C: O(1)
    pub fn may_reinit(&self, opt_atgc: bool, elapsed_time: u64) -> bool {
        opt_atgc && !self.enabled && elapsed_time >= self.age_threshold
    }

    /// Start a search.
    ///
    /// The oldest end is reset because it describes this search's candidates;
    /// the newest end is not, because it describes the volume. The set is
    /// emptied here as well as at the end of a search, so that a search
    /// abandoned before its release cannot leave its candidates to be costed
    /// by the next one against a span they do not belong to.
    /// # C: O(candidates)
    pub fn begin(&mut self) {
        self.tree.clear();
        self.dirty_min_mtime = u64::MAX;
    }

    /// Offer one section to the search.
    ///
    /// `live` is the section's live blocks and `cp_disabled` says the mount
    /// cannot checkpoint, which together exclude a section holding nothing:
    /// with no checkpoint to retire them, its blocks cannot come back, so
    /// cleaning it would move nothing and free nothing. A caller looking for
    /// a segment to REUSE rather than a section to clean passes `false` —
    /// the exclusion is about reclaim, and reuse does not reclaim.
    ///
    /// The span is widened before the threshold is applied, so a section that
    /// is itself the newest thing seen makes every older candidate's age
    /// larger. That is the point: age is relative to the newest, and a
    /// section can only be judged young against something.
    /// # C: O(log candidates)
    pub fn add_candidate(&mut self, segno: u32, mtime: u64, live: u32, cp_disabled: bool) {
        if cp_disabled && live == 0 { return; }
        // A section with nothing live reports no age; there is no position on
        // the timeline to put it at, and admitting one would drag the newest
        // end of the span to the end of the number line.
        if mtime == INVALID_MTIME { return; }
        if mtime < self.dirty_min_mtime { self.dirty_min_mtime = mtime; }
        if mtime > self.dirty_max_mtime { self.dirty_max_mtime = mtime; }
        if self.dirty_max_mtime - mtime < self.age_threshold { return; }
        self.tree.insert((mtime, segno));
    }

    /// Forget this search's candidates. # C: O(candidates)
    pub fn release(&mut self) { self.tree.clear(); }

    /// Candidates the search has collected. # C: O(1)
    pub fn victim_count(&self) -> u32 { self.tree.len() as u32 }

    /// Candidates one search will cost before it settles for the best so far.
    ///
    /// The larger of a fixed count and a share of what was collected: the
    /// count keeps a search over few candidates worth making, and the share
    /// keeps a search over many from costing the whole volume for a decision
    /// that only has to be good.
    /// # C: O(1)
    pub fn dirty_threshold(&self) -> u32 {
        let share = self.candidate_ratio
            .saturating_mul(self.victim_count())
            / PERCENT as u32;
        self.max_candidate_count.max(share)
    }

    /// The oldest and newest ages the cost is measured between. # C: O(1)
    pub fn mtime_span(&self) -> (u64, u64) { (self.dirty_min_mtime, self.dirty_max_mtime) }

    /// The scale both halves of a cost are computed on, for a span of ages.
    ///
    /// Capped, and that cap is what keeps the sum of the two halves inside
    /// the range the cost is subtracted from: each half is at most the scale
    /// times a whole percentage, so their sum is at most twice the scale
    /// times `PERCENT`, which the ceiling comfortably holds.
    /// # C: O(1)
    pub(super) fn accuracy(total_time: u64) -> u64 {
        if total_time == 0 { return DEFAULT_ACCURACY_CLASS; }
        (u64::MAX / total_time / PERCENT).min(DEFAULT_ACCURACY_CLASS)
    }
}

#[cfg(test)]
#[path = "../tests/atgc/candidates.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/atgc/enable.rs"]
mod enable_tests;
