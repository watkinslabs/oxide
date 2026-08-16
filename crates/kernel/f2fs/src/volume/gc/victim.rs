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

/// The segment to clean next, or `None` when none is worth it.
///
/// `skip` holds segments a caller has already tried and failed to empty.
/// Without it a victim whose blocks all turn out unmigratable is chosen again
/// on the next pass, forever.
/// # C: O(segments)
pub fn pick(segs: &[SegInfo], per_seg: u16, policy: Policy, skip: &[u32]) -> Option<u32> {
    let (min_mtime, max_mtime) = mtime_span(segs, per_seg);
    let mut best: Option<(u64, u32)> = None;
    for s in segs {
        if !eligible(s, per_seg) { continue; }
        if skip.contains(&s.segno) { continue; }
        let c = cost(policy, s, per_seg, min_mtime, max_mtime);
        // A tie goes to the lowest segment number rather than to whichever
        // entry came first, so the answer does not depend on how the caller
        // ordered the table.
        let better = best.is_none_or(|(bc, bs)| c < bc || (c == bc && s.segno < bs));
        if better { best = Some((c, s.segno)); }
    }
    best.map(|(_, segno)| segno)
}
