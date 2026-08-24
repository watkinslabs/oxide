//! Which segment is worth cleaning, decided over the segment table alone.
//!
//! Nothing here reads a medium. A victim is chosen from a snapshot of counts
//! and timestamps, so the policy — the part that decides how much work the
//! cleaner does and whether it makes progress at all — is checkable without a
//! volume behind it.
//!
//! Two costs, and a smaller cost always wins:
//!
//! - **Greedy** costs a segment by its live blocks. Cleaning the emptiest
//!   segment moves the fewest blocks per segment reclaimed, which is what a
//!   caller that needs space NOW wants.
//! - **Cost-benefit** weighs the same liveness against age. A segment written
//!   long ago and still only half live is unlikely to empty on its own; a
//!   segment written moments ago probably will, and cleaning it copies blocks
//!   that were about to be invalidated anyway.
//!
//! Three segments are never victims, and each exclusion prevents a distinct
//! failure: a segment a log holds OPEN would be cleaned underneath the writer
//! that is still appending to it; an EMPTY segment yields nothing, and picking
//! one repeatedly is a cleaner that runs forever and frees nothing; a FULL
//! segment costs one block moved per block reclaimed, which is no reclaim at
//! all.
//!
//! The unit is a SECTION, not a segment. A volume formatted with several
//! segments to the section is allocated and erased in sections, so cleaning
//! one segment of a section leaves the section as unusable as it was and the
//! work is wasted. Costs are therefore summed over the section and the whole
//! of it is cleaned. A volume with one segment to the section — which is the
//! common shape — gets exactly the per-segment answer, by arithmetic rather
//! than by a second code path.
//!
//! The search is BOUNDED and RESUMES. Costing every section of a large volume
//! on every allocation that runs short is work proportional to the volume for
//! a decision that only has to be good, so a search stops after a set number
//! of candidates and the next one starts where it left off. Without the
//! resume the bound would re-cost the same low-numbered sections forever and
//! never reach the rest of the volume.

use alloc::vec::Vec;

/// One segment, as victim selection sees it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SegInfo {
    pub segno: u32,
    /// Blocks the segment table calls live.
    pub live: u16,
    /// When the segment was last written.
    pub mtime: u64,
    /// Whether one of the six logs is appending to it.
    pub current: bool,
}

/// How a candidate is costed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Policy {
    /// Fewest live blocks first.
    Greedy,
    /// Live blocks weighed against age.
    CostBenefit,
}

/// Both costs are defined in percentages, as the format's own arithmetic is.
pub const PERCENT: u64 = 100;
/// The value a benefit is subtracted from, so a LARGER benefit is a SMALLER
/// cost and one comparison serves both policies.
pub const COST_CEILING: u64 = u32::MAX as u64;

/// Whether a segment may be cleaned at all. # C: O(1)
pub fn eligible(s: &SegInfo, per_seg: u16) -> bool {
    !s.current && s.live > 0 && s.live < per_seg
}

/// Greedy cost: the work cleaning would cost, in blocks moved. # C: O(1)
pub fn greedy_cost(live: u16) -> u64 { u64::from(live) }

/// Cost-benefit cost, from liveness and age.
///
/// `age` is 100 for the oldest segment in the table and 0 for the newest, so
/// two segments with the same liveness are separated by which was written
/// first. When every segment carries the same timestamp no segment is older
/// than another and the age term vanishes, which is the same answer the
/// arithmetic gives for a volume that has never recorded a time.
/// # C: O(1)
pub fn cb_cost(live: u16, mtime: u64, min_mtime: u64, max_mtime: u64, per_seg: u16) -> u64 {
    let u = (u64::from(live) * PERCENT) / u64::from(per_seg.max(1));
    let age = if max_mtime <= min_mtime {
        0
    } else {
        PERCENT - (PERCENT * (mtime.saturating_sub(min_mtime))) / (max_mtime - min_mtime)
    };
    COST_CEILING - ((PERCENT * (PERCENT - u.min(PERCENT)) * age) / (PERCENT + u))
}

/// The oldest and newest timestamps among the segments a victim may come from.
///
/// Ineligible segments are left out: an open log's timestamp would stretch the
/// range that every candidate's age is measured against, and change the answer
/// for segments that had nothing to do with it.
/// # C: O(segments)
pub fn mtime_span(segs: &[SegInfo], per_seg: u16) -> (u64, u64) {
    let mut span: Option<(u64, u64)> = None;
    for s in segs.iter().filter(|s| eligible(s, per_seg)) {
        span = Some(match span {
            None => (s.mtime, s.mtime),
            Some((lo, hi)) => (lo.min(s.mtime), hi.max(s.mtime)),
        });
    }
    span.unwrap_or((0, 0))
}

/// One candidate's cost under `policy`. # C: O(1)
pub fn cost(policy: Policy, s: &SegInfo, per_seg: u16, min_mtime: u64, max_mtime: u64) -> u64 {
    match policy {
        Policy::Greedy => greedy_cost(s.live),
        Policy::CostBenefit => cb_cost(s.live, s.mtime, min_mtime, max_mtime, per_seg),
    }
}

/// Candidates costed before a search gives up and takes the best so far.
///
/// The number is the reference's, and the reason it exists is that a victim
/// only has to be a good one: the difference between the best section on a
/// large volume and the best of a few thousand of them is not worth a scan
/// proportional to the volume on every allocation that runs short.
pub const DEF_MAX_VICTIM_SEARCH: u32 = 4096;

/// One section, as victim selection sees it: what a whole erase unit costs.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Unit {
    /// The section's first segment, which is what a caller cleans from.
    pub first: u32,
    /// Live blocks across the whole section.
    pub live: u32,
    /// The section's age, weighted by where its live blocks are.
    pub mtime: u64,
    /// Whether a log is appending anywhere in it.
    pub open: bool,
    /// Whether any segment in it holds some but not all of its blocks —
    /// which is the only shape cleaning can improve.
    pub dirty: bool,
}

/// The sections of a segment table. # C: O(segments)
pub fn units(segs: &[SegInfo], per_seg: u16, segs_per_sec: u32) -> Vec<Unit> {
    let per_sec = segs_per_sec.max(1) as usize;
    segs.chunks(per_sec)
        .map(|c| {
            let live: u32 = c.iter().map(|s| u32::from(s.live)).sum();
            Unit {
                first: c[0].segno,
                live,
                mtime: section_mtime(c),
                open: c.iter().any(|s| s.current),
                dirty: c.iter().any(|s| s.live > 0 && s.live < per_seg),
            }
        })
        .collect()
}

/// A section's age: the mean of its segments' ages, weighted by how much of
/// each is still live.
///
/// An empty segment inside the section carries no weight at all — its
/// timestamp describes blocks that are gone, and letting it drag the mean
/// would age a section by data nothing holds.
/// # C: O(segments per section)
pub fn section_mtime(segs: &[SegInfo]) -> u64 {
    let held: u64 = segs.iter().map(|s| u64::from(s.live)).sum();
    if held == 0 { return 0; }
    let total: u64 = segs.iter().map(|s| s.mtime.saturating_mul(u64::from(s.live))).sum();
    total / held
}

/// Whether a section may be cleaned at all. # C: O(1)
pub fn unit_eligible(u: &Unit) -> bool { !u.open && u.dirty }

/// One section's cost under `policy`.
///
/// Greedy costs the blocks the section would make it move. Cost-benefit
/// weighs the section's mean liveness — its live blocks spread over its
/// segments — against its age, exactly as it does for a lone segment.
/// # C: O(1)
pub fn unit_cost(policy: Policy, u: &Unit, per_seg: u16, segs_per_sec: u32,
                 min_mtime: u64, max_mtime: u64) -> u64 {
    match policy {
        Policy::Greedy => u64::from(u.live),
        Policy::CostBenefit => {
            let avg = (u.live / segs_per_sec.max(1)).min(u32::from(u16::MAX)) as u16;
            cb_cost(avg, u.mtime, min_mtime, max_mtime, per_seg)
        }
    }
}

/// The oldest and newest ages among the sections a victim may come from.
/// # C: O(sections)
pub fn unit_mtime_span(us: &[Unit]) -> (u64, u64) {
    let mut span: Option<(u64, u64)> = None;
    for u in us.iter().filter(|u| unit_eligible(u)) {
        span = Some(match span {
            None => (u.mtime, u.mtime),
            Some((lo, hi)) => (lo.min(u.mtime), hi.max(u.mtime)),
        });
    }
    span.unwrap_or((0, 0))
}

/// How much of the table one search is allowed to look at, and where it
/// starts.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Search {
    pub policy: Policy,
    /// The segment number the scan resumes from.
    pub offset: u32,
    /// Candidates costed before the search settles for the best so far.
    pub max_search: u32,
}

impl Search {
    /// A search for a caller that needs the space NOW: the whole table, from
    /// the start. A bound here would let an allocation fail while a good
    /// victim sat past the cut-off.
    /// # C: O(1)
    pub fn foreground(policy: Policy) -> Self {
        Self { policy, offset: 0, max_search: u32::MAX }
    }

    /// A search for a caller cleaning ahead of demand, which is bounded and
    /// resumes where the last one stopped.
    ///
    /// The bound is passed in rather than taken from the default, because it is
    /// the one thing about an ahead-of-demand pass a tool can change: a volume
    /// whose sections are cheap to cost wants a wider search, and one under a
    /// latency budget wants a narrower one.
    /// # C: O(1)
    pub fn background(policy: Policy, offset: u32, max_search: u32) -> Self {
        Self { policy, offset, max_search }
    }
}

/// The victim a search settled on, and where the next one should resume.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Found {
    /// The first segment of the chosen section.
    pub segno: u32,
    /// The offset the next search starts from.
    pub cursor: u32,
}

/// The section to clean next, under a bounded, resuming search.
///
/// `skip` holds sections a caller has already tried and failed to empty.
/// Without it a victim whose blocks all turn out unmigratable is chosen again
/// on the next pass, forever.
///
/// A tie goes to whichever candidate the scan reached first, which is what
/// makes the cursor mean anything: breaking ties by segment number instead
/// would send every equal-cost search back to the lowest section.
/// # C: O(min(sections, max_search))
pub fn pick_unit(us: &[Unit], per_seg: u16, segs_per_sec: u32, search: Search, skip: &[u32])
    -> Option<Found> {
    pick_unit_with_valid_thresh(us, per_seg, segs_per_sec, search, skip, 100)
}

/// One-time-GC selection with Linux's live-block ratio ceiling. # C: O(min(sections, max_search))
pub fn pick_unit_with_valid_thresh(us: &[Unit], per_seg: u16, segs_per_sec: u32,
                                   search: Search, skip: &[u32], valid_thresh_ratio: u32)
    -> Option<Found> {
    if us.is_empty() { return None; }
    let per_sec = segs_per_sec.max(1);
    let (min_mtime, max_mtime) = unit_mtime_span(us);
    let total = us.len() as u32 * per_sec;
    let start = ((search.offset / per_sec) as usize) % us.len();
    let mut best: Option<(u64, u32)> = None;
    let mut searched = 0u32;
    let mut cursor = search.offset % total;
    for i in 0..us.len() {
        let u = &us[(start + i) % us.len()];
        if !unit_eligible(u) || skip.contains(&u.first) { continue; }
        let capacity = u64::from(per_seg) * u64::from(per_sec);
        let over_valid = u64::from(u.live) * 100
            >= capacity.saturating_mul(u64::from(valid_thresh_ratio));
        let c = if valid_thresh_ratio < 100 && over_valid {
            COST_CEILING
        } else {
            unit_cost(search.policy, u, per_seg, per_sec, min_mtime, max_mtime)
        };
        if best.is_none_or(|(bc, _)| c < bc) { best = Some((c, u.first)); }
        searched += 1;
        cursor = (u.first + per_sec) % total;
        if searched >= search.max_search { break; }
    }
    best.map(|(_, segno)| Found { segno, cursor })
}

/// The segment to clean next, over a table of lone segments.
///
/// The segment-granular answer is the section-granular one for a volume with
/// one segment to the section, so it is that call rather than a second
/// policy: two implementations of one decision are two answers that can
/// disagree.
/// # C: O(segments)
pub fn pick(segs: &[SegInfo], per_seg: u16, policy: Policy, skip: &[u32]) -> Option<u32> {
    let us = units(segs, per_seg, 1);
    pick_unit(&us, per_seg, 1, Search::foreground(policy), skip).map(|f| f.segno)
}
