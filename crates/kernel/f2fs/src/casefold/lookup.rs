//! How many passes a lookup in a case-folding directory makes.
//!
//! A hash-directed lookup reads two-or-four blocks per level. That is the
//! whole reason the hash exists, and for a directory whose entries were all
//! written under the encoding in force today it is also always right.
//!
//! It is not right for a directory that outlived an encoding change. An entry
//! written when the fold produced different bytes carries the hash of THOSE
//! bytes, so today's fold sends the lookup to a bucket the entry is not in and
//! the name reads as absent while `read_dir` still lists it. The repair is a
//! second pass with the hash ignored: every bucket, every block, comparing
//! names only. It costs the whole directory, so it runs only after the cheap
//! pass has found nothing, and only when the mount has not been told it is
//! unnecessary.
//!
//! Who decides: the mount's `lookup_mode` option, which the volume can veto in
//! only one direction — a superblock flag asserting no entry predates the
//! current encoding turns the automatic choice off, but cannot turn off a
//! rescan the mount asked for outright.
//!
//! There is no linear-ONLY mode. Even the compatibility mode hashes first,
//! because for every entry written under the current encoding the hash is
//! correct and cheap; the linear pass is a fallback, never a replacement.

use super::encoding::Casefold;

/// What a mount asked for.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LookupMode {
    /// Trust the hash. One pass, always.
    Perf,
    /// Assume entries may predate the encoding. Always rescan on a miss.
    Compat,
    /// Rescan on a miss unless the volume says no entry predates the encoding.
    Auto,
}

/// What a mount gets when it asks for nothing: the hash is trusted.
pub const DEFAULT_LOOKUP_MODE: LookupMode = LookupMode::Perf;

impl LookupMode {
    /// Parse the option's value. # C: O(1)
    pub fn parse(value: &[u8]) -> Option<LookupMode> {
        match value {
            b"perf"   => Some(LookupMode::Perf),
            b"compat" => Some(LookupMode::Compat),
            b"auto"   => Some(LookupMode::Auto),
            _         => None,
        }
    }

    /// The value a mount reports back. # C: O(1)
    pub fn name(self) -> &'static str {
        match self {
            LookupMode::Perf   => "perf",
            LookupMode::Compat => "compat",
            LookupMode::Auto   => "auto",
        }
    }
}

/// One pass of a lookup.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Pass {
    /// Search only the bucket the query's hash names, per level.
    Hash,
    /// Every bucket, every block, ignoring each entry's stored hash.
    Linear,
}

/// The passes a lookup makes, in order.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Plan {
    /// One pass. A miss is an absence.
    HashOnly,
    /// A miss in the first pass is not yet an absence.
    HashThenLinear,
}

impl Plan {
    /// The passes to run, in order, stopping at the first that finds the name.
    /// # C: O(1)
    pub fn passes(self) -> &'static [Pass] {
        match self {
            Plan::HashOnly       => &[Pass::Hash],
            Plan::HashThenLinear => &[Pass::Hash, Pass::Linear],
        }
    }
}

/// Would a miss be rescanned without the hash?
///
/// `no_compat_fallback` is the superblock's assertion that no entry predates
/// the current encoding. It answers the automatic mode and nothing else: a
/// mount that asked for the rescan outright still gets it.
/// # C: O(1)
pub fn fallback_to_linear(mode: LookupMode, no_compat_fallback: bool) -> bool {
    match mode {
        LookupMode::Perf   => false,
        LookupMode::Compat => true,
        LookupMode::Auto   => !no_compat_fallback,
    }
}

/// The plan for a lookup in `casefolded`-or-not directory under `mode`.
///
/// A directory that does not fold has one hash per name and no history to be
/// wrong about, so it never rescans however the mount was configured.
/// # C: O(1)
pub fn plan(casefolded: bool, mode: LookupMode, no_compat_fallback: bool) -> Plan {
    if casefolded && fallback_to_linear(mode, no_compat_fallback) {
        Plan::HashThenLinear
    } else {
        Plan::HashOnly
    }
}

/// [`plan`], reading the superblock's assertion off a loaded encoding.
/// # C: O(1)
pub fn plan_for(casefolded: bool, mode: LookupMode, cf: &Casefold) -> Plan {
    plan(casefolded, mode, cf.no_compat_fallback())
}
