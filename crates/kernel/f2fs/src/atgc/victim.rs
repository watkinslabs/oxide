//! Costing the collected candidates, and the two questions asked of them.
//!
//! Both questions walk the same age-ordered set and both settle for a good
//! answer rather than the best one — the walk stops after a bounded number of
//! candidates, because costing every section of a large volume on every pass
//! is work proportional to the volume for a decision that only has to be
//! good. Which candidates the bound reaches is therefore part of the answer,
//! and that is why the order is over ages rather than over segment numbers:
//! the bound spends its budget on the oldest sections, which are the ones the
//! policy exists to find.
//!
//! - **Cleaning** starts at the oldest candidate and walks towards the newest.
//!   Its cost mixes age with emptiness in a stated ratio, so a slightly newer
//!   but much emptier section can still win.
//! - **Reuse** starts at the candidate nearest a wanted age and walks OUTWARDS
//!   in both directions. Its cost is emptiness alone, with nearness to the
//!   wanted age as the tiebreak: the caller is placing a write of a known age
//!   beside data of the same age, so that the segment they share falls due
//!   together rather than leaving one survivor to be copied.
//!
//! Costs are inverted — subtracted from a ceiling — so that a LARGER benefit
//! is a SMALLER cost and one comparison serves both, exactly as the two
//! occupancy-based costs do.

use super::state::Atgc;
use crate::volume::gc::victim::{COST_CEILING, PERCENT};

/// The candidate a search settled on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Pick {
    /// The section's first segment, which is what a caller cleans or reuses.
    pub segno: u32,
    /// What it was costed at. Smaller is better.
    pub cost: u32,
    /// The age term that cost was reached with, which is what separates two
    /// candidates the cost could not.
    pub age: u64,
}

/// A running best-so-far, so both searches share one comparison rule.
struct Best {
    pick: Option<Pick>,
    cost: u32,
    age: u64,
}

impl Best {
    /// A search that has costed nothing.
    ///
    /// Opening at the ceiling is what makes a candidate of no benefit at all
    /// lose to no candidate: its cost equals the ceiling, and the tiebreak
    /// needs an age strictly greater than none.
    /// # C: O(1)
    fn new() -> Self { Self { pick: None, cost: COST_CEILING as u32, age: 0 } }

    /// Take the candidate if it beats what is held, or ties and is older.
    /// # C: O(1)
    fn offer(&mut self, segno: u32, cost: u32, age: u64) {
        if cost < self.cost || (cost == self.cost && age > self.age) {
            self.cost = cost;
            self.age = age;
            self.pick = Some(Pick { segno, cost, age });
        }
    }
}

impl Atgc {
    /// The section worth cleaning, by age weighed against emptiness.
    ///
    /// `live_of` gives a section's live blocks; `sec_blocks` is how many it
    /// holds when full. Nothing here reads a medium, so the same decision is
    /// checkable against a table that was never written.
    /// # C: O(min(candidates, the search bound) * log candidates)
    pub fn lookup_victim(&self, sec_blocks: u32, live_of: &dyn Fn(u32) -> u32) -> Option<Pick> {
        let (min_mtime, top) = self.mtime_span();
        if top < min_mtime { return None; }
        // Past the newest, not at it: a span of one age must still be a span,
        // or the newest candidate would divide by nothing.
        let max_mtime = top.saturating_add(1);
        let total_time = max_mtime - min_mtime;
        let accu = Self::accuracy(total_time);
        let bound = self.dirty_threshold();
        let weight = u64::from(self.age_weight.min(PERCENT as u32));
        let span = u64::from(sec_blocks.max(1));
        let mut best = Best::new();
        let mut iter = 0u32;
        for &(mtime, segno) in self.tree.iter() {
            // A candidate outside the span belongs to an earlier search whose
            // release did not happen; it is passed over WITHOUT spending any
            // of the bound, so a stale entry cannot crowd out a live one.
            if mtime >= min_mtime && mtime < max_mtime {
                let age = accu * (max_mtime - mtime) / total_time * weight;
                let free = u64::from(sec_blocks.saturating_sub(live_of(segno)));
                let empty = accu * free / span * (PERCENT - weight);
                let cost = COST_CEILING.saturating_sub(age + empty) as u32;
                iter += 1;
                best.offer(segno, cost, age);
            }
            if iter >= bound { break; }
        }
        best.pick
    }

    /// The segment worth reusing for a write of age `target_age`.
    ///
    /// `blks_per_seg` is how many blocks a segment holds when full, and a
    /// segment already holding that many is passed over: reuse needs a free
    /// slot, and a full segment has none.
    /// # C: O(min(candidates, the search bound) * log candidates)
    pub fn lookup_ssr_victim(&self, target_age: u64, blks_per_seg: u32,
                             live_of: &dyn Fn(u32) -> u32) -> Option<Pick> {
        let (min_mtime, top) = self.mtime_span();
        if top < min_mtime { return None; }
        let max_mtime = top.saturating_add(1);
        let bound = self.dirty_threshold();
        let start = self.seek(target_age);
        let mut best = Best::new();
        // Two passes from the same starting candidate: back towards the older
        // ages, then forward towards the newer. One direction alone would
        // make the answer depend on which side of the wanted age the search
        // happened to land.
        for back in [true, false] {
            let mut iter = 0u32;
            let mut cur = start;
            while let Some((mtime, segno)) = cur {
                if mtime >= min_mtime && mtime < max_mtime {
                    let live = live_of(segno);
                    if live != blks_per_seg {
                        iter += 1;
                        let age = max_mtime - mtime;
                        let near = max_mtime.saturating_sub(target_age.abs_diff(age));
                        let cost = COST_CEILING.saturating_sub(u64::from(live)) as u32;
                        best.offer(segno, cost, near);
                    }
                }
                if iter >= bound { break; }
                cur = if back { self.before(mtime, segno) } else { self.after(mtime, segno) };
            }
        }
        best.pick
    }

    /// Where a walk outwards from `target` starts: the newest candidate at or
    /// before it, or the oldest of all when every candidate is newer.
    ///
    /// A single well-defined starting point rather than whichever node a tree
    /// descent happened to end on. Both directions are walked from it, so the
    /// choice only shifts the window by one candidate — but it shifts it the
    /// same way every time, which a shape-dependent choice would not.
    /// # C: O(log candidates)
    fn seek(&self, target: u64) -> Option<(u64, u32)> {
        self.tree.range(..=(target, u32::MAX)).next_back()
            .or_else(|| self.tree.iter().next())
            .copied()
    }

    /// The candidate one step older. # C: O(log candidates)
    fn before(&self, mtime: u64, segno: u32) -> Option<(u64, u32)> {
        self.tree.range(..(mtime, segno)).next_back().copied()
    }

    /// The candidate one step newer. # C: O(log candidates)
    fn after(&self, mtime: u64, segno: u32) -> Option<(u64, u32)> {
        use core::ops::Bound::{Excluded, Unbounded};
        self.tree.range((Excluded((mtime, segno)), Unbounded)).next().copied()
    }
}

#[cfg(test)]
#[path = "../tests/atgc/cost.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/atgc/equivalence.rs"]
mod equivalence_tests;

#[cfg(test)]
#[path = "../tests/atgc/ssr.rs"]
mod ssr_tests;
