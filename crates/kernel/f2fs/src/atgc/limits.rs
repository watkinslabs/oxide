//! The numbers age-threshold cleaning is defined in.
//!
//! Every one of them is part of the policy's arithmetic rather than a local
//! convenience, so each is named here and none is written at a use site: the
//! cost formula is only checkable against the format if the scale it is
//! computed on has a name.

/// Sections younger than this are never candidates: seven days, in seconds.
pub const DEF_AGE_THRESHOLD: u64 = 60 * 60 * 24 * 7;

/// The share of the collected candidates, in percent, one search will cost.
pub const DEF_CANDIDATE_RATIO: u32 = 20;

/// Candidates one search will cost whatever that share works out to. The
/// bound is the LARGER of the two, so a volume with few candidates still gets
/// a search worth making.
pub const DEF_MAX_CANDIDATE_COUNT: u32 = 10;

/// How much of a candidate's cost is its age rather than its emptiness, in
/// percent. The remainder is the emptiness weight; the two always sum to
/// `PERCENT`, which is why only one of them is stored.
pub const DEF_AGE_WEIGHT: u32 = 60;

/// The fixed-point scale both halves of the cost are computed on.
///
/// Neither half has a natural unit — one is a position in a time span, the
/// other a share of a section — so both are scaled to a common integer range
/// and added. The scale is capped rather than derived so that the sum cannot
/// leave the range the cost is subtracted from.
pub const DEFAULT_ACCURACY_CLASS: u64 = 10_000;

/// The age a section with no live block reports, which is no age at all: its
/// timestamp describes data that is gone.
pub const INVALID_MTIME: u64 = u64::MAX;
