//! The four controls age-threshold cleaning is tuned by.
//!
//! Bounds are refusals, not clamps: a tool that asks for a weight of two
//! hundred percent has misunderstood the unit, and quietly giving it one
//! hundred leaves it believing otherwise forever.
//!
//! Two of the four carry a bound the format states and two do not. Where the
//! format states none, the field's own width is the bound and a value past it
//! is REFUSED rather than truncated — a count of four billion and one that
//! silently becomes one is the worst of both answers.

use syscall::errno::Errno;

use super::state::Atgc;
use crate::volume::gc::victim::PERCENT;

/// One writable control.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Knob {
    /// Share of the collected candidates one search costs.
    CandidateRatio,
    /// Candidates one search costs regardless of that share.
    CandidateCount,
    /// How much of a cost is age rather than emptiness.
    AgeWeight,
    /// Age a section must reach before it may be a candidate.
    AgeThreshold,
}

/// The name the control is published under. # C: O(1)
pub fn name(k: Knob) -> &'static str {
    match k {
        Knob::CandidateRatio => "atgc_candidate_ratio",
        Knob::CandidateCount => "atgc_candidate_count",
        Knob::AgeWeight => "atgc_age_weight",
        Knob::AgeThreshold => "atgc_age_threshold",
    }
}

/// Every control, in the order they are published. # C: O(1)
pub const ALL: &[Knob] = &[
    Knob::CandidateRatio, Knob::CandidateCount, Knob::AgeWeight, Knob::AgeThreshold,
];

/// The number a control reads back as. # C: O(1)
pub fn show(a: &Atgc, k: Knob) -> u64 {
    match k {
        Knob::CandidateRatio => u64::from(a.candidate_ratio),
        Knob::CandidateCount => u64::from(a.max_candidate_count),
        Knob::AgeWeight => u64::from(a.age_weight),
        Knob::AgeThreshold => a.age_threshold,
    }
}

/// Whether a value is one the control will take. # C: O(1)
pub fn accepts(k: Knob, v: u64) -> Result<(), Errno> {
    let ok = match k {
        // Both are percentages of something, and neither has a meaning past
        // the whole of it: a ratio over one hundred asks for more candidates
        // than were collected, and a weight over one hundred would make the
        // emptiness half of the cost negative.
        Knob::CandidateRatio | Knob::AgeWeight => v <= PERCENT,
        Knob::CandidateCount => v <= u64::from(u32::MAX),
        // An age is measured in the same seconds the volume records, and the
        // volume records them in a full word.
        Knob::AgeThreshold => true,
    };
    if ok { Ok(()) } else { Err(Errno::Einval) }
}

/// Turn one control, refusing a value it will not take.
///
/// A refused write changes nothing at all.
/// # C: O(1)
pub fn store(a: &mut Atgc, k: Knob, v: u64) -> Result<(), Errno> {
    accepts(k, v)?;
    match k {
        Knob::CandidateRatio => a.candidate_ratio = v as u32,
        Knob::CandidateCount => a.max_candidate_count = v as u32,
        Knob::AgeWeight => a.age_weight = v as u32,
        Knob::AgeThreshold => a.age_threshold = v,
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/atgc/knobs.rs"]
mod tests;
